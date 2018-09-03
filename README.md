# soap-class
Класс php для подключения к веб-сервису SOAP


How to use:

1. Set services in SoapClass private services property

2. use:

require 'SoapClass.php';

//login, password, different servers time
$SoapClass = new SoapClass('E_PARTNER', 'ALFAE313', -80);


//class->service->method
$UPID = $SoapClass->PartnersInteraction->getUPID([
	'callerCode' => '12345',
])->UPID;

//class->service->method
$result = $SoapClass->GetContractSigned->GetContractSigned([
	'UPID' => $UPID,
  'ContractId' => 46164828,
]);
