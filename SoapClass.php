<?php

/**
 * Класс для подключения к веб-сервису
 *
 * Пример использования:
 *
 * $SoapClass = new SoapClass('Логин', 'Пароль', $разницаВремени = -80);
 * $result = $SoapClass->имяСервиса->имяМетода($массивПараметров);
 * if( $result ) print_r($result); //Успех
 * else echo $SoapClass->lastErrorMessage; //Сообщение об ошибке
 */
 class SoapClass
 {
 	/**
 	 * Список сервисов.
 	 *
 	 * @property string $wsdl Путь к wsdl-файлу сервиса
 	 * @property boolean $need_auth Нужна авторизация на сервисе?
 	 */
 	private $services = [
     'KiasSVC' => [
       'wsdl' => 'https://kiassvctest.nasko.ru/kiassvctest/KiasSVC.asmx?WSDL',
       'need_auth' => false,
     ],
   ];

 	/**
 	 * @property SoapClient|null Последний выбранный сервис
 	 */
 	public $lastService = null;

 	/**
 	 * @property array Кэш SOAP-соединений
 	 */
 	private $soapClient = [];

 	/**
 	 * @property array Цепочка активных сервисов
 	 */
   private $selectedService = [];

 	/**
 	 * @property string Логин для авторизации
 	 */
   private $user;

 	/**
 	 * @property string Пароль для авторизации
 	 */
   private $pass;

 	/**
 	 * @property int Отклонение времени в секундах клиентской машины от серверной
 	 */
   private $timeDifference;

 	/**
 	 * @property string|null Текст последней ошибки
 	 */
 	public $lastErrorMessage = null;

   public function __construct($user = '', $pass = '', $timeDifference = 0){
     $this->user = $user;
     $this->pass = $pass;
     $this->timeDifference = $timeDifference;
   }

 	/**
 	 * Подключается к серверу первый раз, второй раз выдает соединение из кэша
 	 * @param string $serviceName Имя сервиса
 	 * @return SoapClient
 	 */
 	private function getSoapClient($serviceName)
 	{
     if(isset($this->soapClient[$serviceName]) && !$this->services[$serviceName]['need_auth']){
       return $this->soapClient[$serviceName];
     }

     $this->soapClient[$serviceName] = new SoapClient($this->services[$serviceName]['wsdl'], array(
 			"trace" => 1,
 			"exceptions" => 1,
 			"location" => "https://kiassvctest.nasko.ru/kiassvctest/KiasSVC.asmx",
 		));

     if( $this->services[$serviceName]['need_auth'] ){
       $this->soapClient[$serviceName]->__setSoapHeaders([new WsseAuthHeader(
         $this->user,
         $this->pass,
         $this->timeDifference
       )]);
     }

     return $this->soapClient[$serviceName];
 	}

 	/**
 	 * Перегрузка свойств класса - только для выбора сервиса
 	 * @param string $serviceName Имя сервиса
 	 * @return $this
 	 */
   public function __get($serviceName) {
     if( isset($this->services[$serviceName]) ){
       array_push($this->selectedService, $serviceName);
 			$this->lastErrorMessage = null;
     }else{
 			$this->lastErrorMessage = "Service '$serviceName' not found!";
 		}
 		return $this;
   }

 	/**
 	 * Перегрузка методов класса - только для работы с методами сервисов
 	 * @param string $methodName Имя метода
 	 * @param array $args Аргументы метода
 	 * @return object|bool Возвращает объект или false
 	 */
   public function __call($methodName, $args){
 		if( !empty($this->lastErrorMessage) ){
 			return false;
 		}
     try{
 			$service = array_pop($this->selectedService);
 			$this->lastService = $this->getSoapClient($service);
 			return $this->lastService->{$methodName}($args[0]);
 		}catch(SoapFault $exception){
 			$this->lastErrorMessage = $exception->getMessage();
 			return false;
 		}
   }
 }



 /**
  * Вспомогательный класс для авторизации на серверной машине
  */
 class WsseAuthHeader extends SoapHeader {

   private $wss_ns = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
   private $wsu_ns = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
   private $type_password_digest= 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest';
   private $type_password_text= 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText';
   private $encoding_type_base64 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

   private $timeDifference;

   private function authText($user, $pass) {
       $auth = new stdClass();
       $auth->Username = new SoapVar($user, XSD_STRING, NULL, $this->wss_ns, NULL, $this->wss_ns);
       $auth->Password = new SoapVar('<ns2:Password Type="'.$this->type_password_text.'">' . $pass . '</ns2:Password>', XSD_ANYXML );
       return $auth;
   }

   private function authDigest($user, $pass) {
       $created = gmdate('Y-m-d\TH:i:s\Z', time()+$this->timeDifference);
       $nonce = mt_rand();
       $enpass = base64_encode(pack('H*', sha1(pack('H*', $nonce) . pack('a*', $created) . pack('a*', $pass))));
       $auth = new stdClass();
       $auth->Username = new SoapVar($user, XSD_STRING, NULL, $this->wss_ns, NULL, $this->wss_ns);
       $auth->Password = new SoapVar('<ns2:Password Type="'.$this->type_password_digest.'">' . $enpass . '</ns2:Password>', XSD_ANYXML );
       $auth->Nonce = new SoapVar('<ns2:Nonce EncodingType="' . $this->encoding_type_base64 . '">' . base64_encode(pack('H*', $nonce)) . '</ns2:Nonce>', XSD_ANYXML);
       $auth->Created = new SoapVar($created, XSD_STRING, NULL, $this->wss_ns, NULL, $this->wsu_ns);
       return $auth;
   }

   public function __construct($user, $pass, $timeDifference, $useDigest=true) {
       $this->timeDifference = $timeDifference;

       if ($useDigest) {
           $auth = $this->authDigest($user, $pass);
       }else{
           $auth = $this->authText($user, $pass);
       }
       $username_token = new stdClass();
       $username_token->UsernameToken = new SoapVar($auth, SOAP_ENC_OBJECT, NULL, $this->wss_ns, 'UsernameToken', $this->wss_ns);

       $security_sv = new SoapVar(
           new SoapVar($username_token, SOAP_ENC_OBJECT, NULL, $this->wss_ns, 'UsernameToken', $this->wss_ns),
           SOAP_ENC_OBJECT, NULL, $this->wss_ns, 'Security', $this->wss_ns);
       parent::__construct($this->wss_ns, 'Security', $security_sv, true);
   }
 }
 ?>
