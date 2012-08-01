<?php

/**
 * Validate Mail Class
 *
 * @license http://www.freebsd.org/copyright/freebsd-license.html FreeBSD Licence
 * @author roberto@nygaard.es - Roberto Nygaard - @topikito - github.com/topikito
 * @version 0.1
 * 
 * @example
 *	$emails = array(...);
 *	$ValidateMail = new ValidateMail();
 *	$result = $ValidateMail->checkEmails($emails);
 */
class ValidateMail
{
	const DEBUG_MODE = false;
	const MAX_READ_TIME = 6;
	const MAX_CONN_TIME = 30;
	const SOCKET_READ_SIZE = 2082;
	const SOCKET_CODE_SUCCESS = 220;
	const SMTP_CODE_ACCEPTED = 250;
	const SMTP_CODE_EMAIL_REJECTED = 550;
	const SMTP_CODE_GREYLISTED_1 = 451;
	const SMTP_CODE_GREYLISTED_2 = 452;
	const SMTP_CODE_SYNTAX_ERROR = 501;
	const LEVEL_MORPHOLOGIC = 0;
	const LEVEL_BLACKLIST = 1;
	const LEVEL_DNS = 2;
	const LEVEL_SMTP = 3;
	const CHECK_SUCCESS = 1000;
	const CHECK_ERROR_MORPHO = 1001;
	const CHECK_ERROR_BLACKLIST = 1002;
	const CHECK_ERROR_DNS = 1003;
	const CHECK_ERROR_SMTP = 1004;
	const CHECK_ERROR_SERVER_UNKNOWN = 1005;

	private $_errorCode = array(
		1001 => 'MORPHOLOGICAL ERROR',
		1002 => 'IN_BLACKLIST',
		1003 => 'DNS_ERROR',
		1004 => 'SMTP_ERROR',
		1005 => 'SERVER_ERROR'
	);

	/**
	 * Specifies if we match with the black list dictionary
	 * @var bool
	 */
	private $_enableBlackList = true;

	/**
	 * Dictionary with domains known for being "trash emails"
	 * @var array
	 */
	protected $_emailDomainsBlackList = array(
		'guerrillamail.com', 'guerrillamailblock.com',
		'guerrillamail.net', 'guerrillamail.biz',
		'guerrillamail.org', 'guerrillamail.de',
		'sharklasers.com', 'spambox.us',
		'rtrtr.com', '10minutemail.com',
		'10minutemail.com', 'mailexpire.com',
		'mailzilla.org', 'hidzz.com',
		'mailcatch.com', 'incognitomail.org',
		'tempemail.net', 'mintemail.com',
		'spamgourmet.com', 'nobulk.com',
		'spaml.com', 'spamify.com',
		'mailnull.com', 'deadaddress.com',
		'emailmiser.com', 'e4ward.com',
		'sneakemail.com', 'mailme.lv',
		'emailwarden.com', 'saynotospams.com',
		'fakedemail.com', 'incognitomail.org',
		'pookmail.com', 'mailinator.com',
		'mailmetrash.com', 'thankyou2010.com',
		'trash2009.com', 'mt2009.com',
		'trashymail.com', 'mytrashmail.com',
		'jetable.org', 'maileater.com',
		'spamhole.com', 'kasmail.com',
		'spammotel.com', 'shieldemail.com',
		'teleworm.us', 'blockfilter.com',
		'gishpuppy.com', 'spamex.com',
		'shortmail.net', 'dontreg.com',
		'tempomail.fr', 'tempemail.net',
		'spamfree24.org', 'kasmail.com',
		'spammotel.com', 'greensloth.com',
		'spamspot.com'
	);
	private $_allValid = true;
	private $_sock;
	private $_result;
	private $_local;
	private $_domain;
	private $_domains;
	private $_smtpPort = 25;
	private $_fromUser = 'user';
	private $_fromDomain = 'localhost';

	/**
	 * Specifies the level of paranoia:
	 * 0.- Checks ONLY the morphology of the email
	 * 1.- Level 0 + BlackList checking
	 * 2.- Level 1 + Checks the DNS Records of the domain
	 * 3.- Level 2 + Asks the SMTP server for the email
	 * @var int
	 */
	private $_levelOfParanoia = self::LEVEL_DNS;

	/**
	 * We add the email as invalid and specify the reason why its so.
	 * @param string $email
	 * @param string $reason
	 */
	protected function _markInvalidEmail($reason, $email = null)
	{
		if ($email === null)
		{
			$email = $this->_local . '@' . $this->_domain;
		}
		$this->_result[$email] = $reason;
		$this->_allValid = false;
	}

	/**
	 *
	 * @param int $reason
	 * @param string[optional] $domain
	 * @return boolean
	 */
	protected function _markInvalidDomain($reason, $domain = null)
	{
		if ($domain === null)
		{
			$domain = $this->_domain;
		}
		foreach ($this->_domains[$domain] as $_local)
		{
			$email = $_local . '@' . $domain;
			$this->_markInvalidEmail($reason, $email);
		}
		unset($this->_domains[$domain]);

		return true;
	}

	/**
	 * This can be better than using a "strpos" method to get the local and the
	 * domain part because some emails can contain more than one '@'
	 *
	 * @param string $email
	 * @return array
	 */
	protected function _parseEmail($email)
	{
		$parts = explode('@', $email);
		$domain = array_pop($parts);
		$local = implode('@', $parts);
		return array($local, $domain);
	}

	/**
	 * Set the Emails to validate
	 * @param $emails Array List of Emails
	 */
	protected function _setEmails($emails)
	{
		foreach ($emails as $email)
		{
			list($local, $domain) = $this->_parseEmail($email);

			if (filter_var($email, FILTER_VALIDATE_EMAIL) === false)
			{
				$this->_markInvalidEmail(self::CHECK_ERROR_MORPHO);
			}
			else
			{
				$this->_result[$email] = true;
				if (!isset($this->_domains[$domain]))
				{
					$this->_domains[$domain] = array();
				}
				$this->_domains[$domain][] = $local;
			}
		}
		return true;
	}

	/**
	 * Set the Email of the sender/validator
	 * @param $email String
	 */
	protected function _setSenderEmail($email)
	{
		list($this->_fromUser, $this->_fromDomain) = $this->_parseEmail($email);
		return true;
	}

	/**
	 * Validate Email Addresses
	 * @param String $emails Emails to validate (recipient emails)
	 * @param String $sender Sender's Email
	 * @return Array Associative List of Emails and their validation results
	 */
	function _validateSMTP()
	{
		// query the MTAs on each Domain
		$mxs = array();
		$dnsRecords = $this->_getDomainMxEntries($this->_domain);
		if ($dnsRecords === false)
		{
			return self::CHECK_ERROR_DNS;
		}
		list($hosts, $mxWeights) = $dnsRecords;

		//Parse MX priorities
		$numOfHosts = count($hosts);
		for ($i = 0; $i < $numOfHosts; $i++)
		{
			$mxs[$hosts[$i]] = $mxWeights[$i];
		}
		asort($mxs);

		//MX Entries. Last one the own domain
		$mxs[] = $this->_domain;

		$this->_debug('[New Domain] '. $this->_domain .': NS entries -> '. print_r($mxs,1));

		$timeout = self::MAX_CONN_TIME / count($hosts);
		while (list($host) = each($mxs))
		{
			// connect to SMTP server
			$this->_debug('>$ telnet ' . $host . ' ' . $this->_smtpPort);
			if ($this->_sock = fsockopen($host, $this->_smtpPort, $errno, $errstr, (float) $timeout))
			{
				stream_set_timeout($this->_sock, self::MAX_READ_TIME);
				break;
			}
		}

		// did we get a TCP socket
		if ($this->_sock)
		{
			$reply = fread($this->_sock, self::SOCKET_READ_SIZE);
			$this->_debug(' ~ '. $reply);

			preg_match('/^([0-9]{3}) /ims', $reply, $matches);
			$code = isset($matches[1]) ? $matches[1] : '';

			$locals = $this->_domains[$this->_domain];
			unset($this->_domains[$this->_domain]);
			//Add the current local that have been popped
			$locals[] = $this->_local;

			$this->_debug('[Locals] -> '. print_r($locals,1));
			if ($code != (string) self::SOCKET_CODE_SUCCESS)
			{
				foreach ($locals as $_local)
				{
					$currentEmail = $_local . '@' .$this->_domain;
					$this->_markInvalidEmail(self::CHECK_ERROR_SERVER_UNKNOWN,$currentEmail);
				}
				return self::CHECK_SUCCESS;
			}

			$this->_tellSocket("HELO " . $this->_fromDomain);
			$reply = $this->_tellSocket("MAIL FROM: <" . $this->_fromUser . '@' . $this->_fromDomain . ">");

			preg_match('/^([0-9]{3}) /ims', $reply, $matches);
			$code = isset($matches[1]) ? $matches[1] : '';

			if ($code == (string) self::SMTP_CODE_SYNTAX_ERROR)
			{
				//Try as sending from the user
				$reply = $this->_tellSocket("MAIL FROM: <" . $this->_local . '@' . $this->_domain  . ">");

				preg_match('/^([0-9]{3}) /ims', $reply, $matches);
				$code = isset($matches[1]) ? $matches[1] : '';

				if ($code != (string) self::SMTP_CODE_ACCEPTED)
				{
					//By default we will assume its ok
					return self::CHECK_SUCCESS;
				}
			}

			// ask for each recepient on this domain
			foreach ($locals as $_local)
			{
				$currentEmail = $_local . '@' .$this->_domain;
				$reply = $this->_tellSocket("RCPT TO: <" . $currentEmail . ">");

				preg_match('/^([0-9]{3}) /ims', $reply, $matches);
				$code = isset($matches[1]) ? $matches[1] : '';

				if ($code == (string) self::SMTP_CODE_EMAIL_REJECTED)
				{
					//We will JUST mark as invalid those where the server
					//tells us as so
					$this->_markInvalidEmail(self::CHECK_ERROR_SMTP,$currentEmail);
				}
			}

			$this->_tellSocket('quit');
			$this->_debug('');
			fclose($this->_sock);
		}
		return self::CHECK_SUCCESS;
	}

	/**
	 * Sends information to the socket
	 * @param string $msg
	 * @return string
	 */
	protected function _tellSocket($msg)
	{
		fwrite($this->_sock, $msg . "\r\n");

		$reply = fread($this->_sock, self::SOCKET_READ_SIZE);

		$this->_debug("[O <-]\n" . $msg);
		$this->_debug("[I ->]\n" . $reply);

		return $reply;
	}

	/**
	 * Retrieves the MX entries of a domain
	 * @param string $domain
	 * @return boolean|array
	 */
	protected function _getDomainMxEntries($domain)
	{
		$hosts = array();
		$mxweights = array();
		$result = getmxrr($domain, $hosts, $mxweights);
		if ($result)
		{
			return array($hosts, $mxweights);
		}
		return false;
	}

	/**
	 * Prints the debug information
	 * @param string $text
	 * @param bool $nl
	 */
	protected function _debug($text, $nl = true)
	{
		if (self::DEBUG_MODE)
		{
			echo htmlentities($text);
			if ($nl)
			{
				echo '<br />' . "\n";
			}
			flush();
		}
	}

	/**
	 * Constructor
	 *
	 * @param string $emails
	 * @return string
	 */
	public function __construct($emails)
	{

		if (!empty($emails))
		{
			$this->checkEmails($emails);
		}

		return $this;
	}
	
	/**
	 * Returns the results of the validation
	 * @return bool|array
	 */
	public function getResult()
	{
		if (empty($this->_result))
		{
			return null;
		}
		
		if ($this->_allValid)
		{
			$this->_result = true;
		}

		return $this->_result;
	}

	/*	 * ******** Setters for private/protected atributes ********* */

	/**
	 * Sets the black list domain array
	 *
	 * @param type $emailDomainsBlackList
	 * @return boolean|string
	 */
	public function setEmailDomainsBlackList($emailDomainsBlackList = array())
	{
		if (empty($emailDomainsBlackList))
		{
			return false;
		}

		if (!is_array($emailDomainsBlackList))
		{
			$emailDomainsBlackList = (array) $emailDomainsBlackList;
		}

		$this->_emailDomainsBlackList = array_flip($emailDomainsBlackList);

		return $this;
	}

	/**
	 * Enables the usage of black listing for domains
	 *
	 * @return string
	 */
	public function enableBlackList()
	{
		$this->_enableBlackList = true;

		return $this;
	}

	/**
	 * Disables the usage of black listing for domains
	 *
	 * @return string
	 */
	public function disableBlackList()
	{
		$this->_enableBlackList = false;

		return $this;
	}

	/*	 * ******** Getters for private/protected atributes ********* */

	/**
	 * Returns the domain black list
	 *
	 * @return array
	 */
	public function getEmailDomainsBlackList()
	{
		return $this->_emailDomainsBlackList;
	}

	/**
	 * Returns the state of the black list check
	 *
	 * @return type
	 */
	public function getBlackListState()
	{
		return $this->_enableBlackList;
	}

	/**
	 * Returns the relation with the ID and the string code error
	 * @return array
	 */
	public function getErrorCodes()
	{
		return $this->_errorCode;
	}

	/** Public functions * */

	/**
	 * Checks if the local (user) of the email is valid
	 *
	 * @param string $local
	 * @return boolean
	 */
	public function checkLocal($local = '')
	{
		if ($this->_levelOfParanoia >= self::LEVEL_SMTP)
		{
			return $this->_validateSMTP();
		}

		return self::CHECK_SUCCESS;
	}

	/**
	 * Checks if the domain of the email is valid
	 *
	 * @param string $domain
	 * @return boolean
	 */
	public function checkDomain($domain = '')
	{
		if (empty($domain))
		{
			$domain = $this->_domain;
		}

		if ($this->_levelOfParanoia >= self::LEVEL_BLACKLIST)
		{
			if ($this->_enableBlackList)
			{
				$host = explode('.', $domain);
				while (count($host) > 2)
				{
					array_shift($host);
				}
				$host = implode('.', $host);

				if (isset($this->_emailDomainsBlackList[$host]))
				{
					return self::CHECK_ERROR_BLACKLIST;
				}
			}
		}

		if ($this->_levelOfParanoia >= self::LEVEL_DNS) //CHECK DNS
		{
			if (!$this->_getDomainMxEntries($domain))
			{
				return self::CHECK_ERROR_DNS;
			}
		}

		return self::CHECK_SUCCESS;
	}

	public function setCheckLevel($level)
	{
		if (!is_int($level))
		{
			return false;
		}

		$this->_levelOfParanoia = $level;
		return $this;
	}

	/**
	 * Checks if an email is valid by checking the local and the domain
	 *
	 * @param array $emails
	 * @return type
	 */
	public function checkEmails($emails)
	{
		if (is_string($emails))
		{
			$emails = (array) $emails;
		}

		//Initialize the emails
		$this->_setEmails($emails);

		//Load the blacklist as a key array so its faster to find
		$this->_emailDomainsBlackList = array_flip($this->_emailDomainsBlackList);

		//Asume the result is already valid
		$this->_allValid = true;

		$domains = array_keys($this->_domains);
		foreach ($domains as $this->_domain)
		{
			$checkCode = $this->checkDomain($this->_domain);
			if ($checkCode > self::CHECK_SUCCESS)
			{
				//This domain aint valid, mark as not valid all the emails
				$this->_markInvalidDomain($checkCode);
				continue;
			}

			while (!empty($this->_domains[$this->_domain]))
			{
				//Check the local part of the email
				$this->_local = array_pop($this->_domains[$this->_domain]);
				$email = $this->_local . '@' . $this->_domain;
				$checkCode = $this->checkLocal($this->_local);
				if ($checkCode > self::CHECK_SUCCESS)
				{
					$this->_markInvalidEmail($checkCode, $email);
				}
			}
		}

		if ($this->_allValid)
		{
			return true;
		}

		return $this->_result;
	}

}