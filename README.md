#ValidateMail

##ValidateMail with vitamins.

For those who just wan't to use it...

###Examples:

```php
require_once 'path/to/validate_email.php';

$emails = array();
$emails = functionThatGivesMeSuspiciousEmails();
$emails[] = 'manual_made@array.example';

$ValidateMail = new ValidateMail();

$resultOfValidation = $ValidateMail->checkEmails($emails);
```
