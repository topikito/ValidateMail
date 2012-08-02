#class ValidateMail() { … }

##Checking emails, but with vitamins.

For those who just wan't to use it...

###Fast examples:

####Basic usage:

~~~ .php
require_once 'path/to/validate_email.php';

$emails = array();
$emails = functionThatGivesMeSuspiciousEmails();
$emails[] = 'manual_made@array.example';

$ValidateMail = new ValidateMail();

$resultOfValidation = $ValidateMail->checkEmails($emails);
~~~

####Specifying level

~~~ .php
require_once 'path/to/validate_email.php';

$emails = array();
$emails = functionThatGivesMeSuspiciousEmails();
$emails[] = 'manual_made@array.example';

//By default, the class uses a level 2 checking
$level = 3;

$ValidateMail = new ValidateMail();

$resultOfValidation = $ValidateMail->setCheckLevel($level)->checkEmails($emails);
~~~

##What's this?

Ok, so now the earlies are done, let's get into the code.

This class/library/util/whateveryouwanttocallit is meant to help yoy validating emails. You may thingk 'Dude, this has already been done!' and I know it, but I coudn't find a full complete library with this level of precision. I will explain:

####Levels?
The validation works by level: you just want to validate morphological emails?? Then you shouldn't use this library, just use the `filter_var()` php function. It works pretty good and it's faster than any regexp you could be able to produce. But above this level, it get's trickier:

#####Level 0 - Morphological
It's really just ment to be used by the higher levels because level n implies n-1 (ok, with n > 0).

This level returns a **1001** error code.

#####Level 1 - Blacklist
Maybe you want to verify if the email is a "real" one to avoid user creating accounts with "rubish" services. They must validate the email, so it doesn't bother you if they use invalid domains. The class provides an array presetted with a list of services I've collected. You can modify the array as you want by setting it to one you specify by using the `public function setEmailDomainsBlackList($emailDomainsBlackList = array())` function.

This level returns a **1002** error code.

#####Level 2 - DNS Records
Ok, if we have passed the previous levels we will now check if the domain itself have 'MX' entries. So that's it, by using the php function `getmxrr()` we will know if the domain have these entries. If the result is `!== false` we pass them as valid.

This level returns a **1003** error code.

#####Level 3 - SMTP Server check
We are now in the maximum paranoid level. This will connect to the domain SMTP server and begin to compose a email. As we add the reciepts, the server will tell us if the mailbox is available or not. This level has an inconvinience: beware that if your IP ain't 100% trustful the SMTP server may check it with the spammers database and if you have records of any suspicious activity it may not accept the connection or reject the `RCPT TO` commands. Also be aware that the SMTP server may block you if you do many connections in a short period of time. You must just use this level by your own risk.

This level returns a **1004** error code.

#####Result
The result comes as a boolean or an array. If all are valid at the selected level, the result will be a boolean. If anyone comes back with an error, the result will be an array with the structure `[<email>] => <result>`, where result can be an error code or a boolean `true` if valid.