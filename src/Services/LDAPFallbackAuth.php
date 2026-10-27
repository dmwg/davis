<?php

namespace App\Services;

use App\Entity\User;
use App\Services\BasicAuth;
use App\Services\LDAPAuth;
use Doctrine\Persistence\ManagerRegistry;
use Sabre\DAV\Auth\Backend\AbstractBasic;

final class LDAPFallbackAuth extends AbstractBasic
{
  
    public const PROVIDER_BASIC = 'Basic';
    public const PROVIDER_LDAP = 'LDAP';
    
    /**
     * LDAP authenticator.
     *
     * @var App\Services\LDAPAuth
     */
    private $LDAPAuth;

    /**
     * Basic authenticator.
     *
     * @var App\Services\BasicAuth
     */
    private $BasicAuth;

    /**
     * Configure which authenticator to check first.
     * 
     * Either 'LDAP' or 'Basic'
     * 
     * @var string
     * 
     */
    private $whichFirst;

    /**
     * Skip LDAP checks for users matching a pattern.
     * 
     * Pattern to match usernames agains
     * 
     * @var string
     * 
     */
    private $skipLdapForUsernames;

    /**
     * Creates the backend object.
     */
    public function __construct(ManagerRegistry $doctrine, Utils $utils, string $LDAPAuthUrl, string $LDAPDnPattern, ?string $LDAPMailAttribute, bool $autoCreate, ?string $LDAPCertificateCheckingStrategy, ?string $whichFirst, ?string $skipLdapForUsernames)
    {
      
        $this->LDAPAuth = new LDAPAuth($doctrine, $utils,  $LDAPAuthUrl, $LDAPDnPattern, $LDAPMailAttribute ?? 'mail', $autoCreate, $LDAPCertificateCheckingStrategy  ?? 'try' );
        $this->BasicAuth = new BasicAuth($doctrine, $utils);
        $this->whichFirst = $whichFirst ?? PROVIDER_BASIC;
        $this->skipLdapForUsernames = $skipLdapForUsernames ?? NULL;
      
        $this->doctrine = $doctrine;
        $this->utils = $utils;
    }

    /**
     * Validates a username and password by trying to authenticate against LDAP and local database.
     *
     * @param string $username
     * @param string $password
     */
    protected function validateUserPass($username, $password): bool
    {
        $skipLdap = false;
        if(!is_null($this->skipLdapForUsernames)){
          $res = preg_match($this->skipLdapForUsernames,$username);
          $skipLdap = ($res == 1);
        }
      
        /*
         * Use the backends.
         */
        switch ($this->whichFirst) {
            case self::PROVIDER_BASIC:
                if(!$this->BasicAuth->validateUserPass($username, $password)){
                  if($skipLdap) return false;
                  return $this->LDAPAuth->validateUserPass($username, $password);
                }else{
                  return true;
                }
            case self::PROVIDER_LDAP:
                if($skipLdap){
                    return $this->BasicAuth->validateUserPass($username, $password);
                }else{
                  if(!$this->LDAPAuth->validateUserPass($username, $password)){
                    return $this->BasicAuth->validateUserPass($username, $password);
                  }else{
                    return true;
                  }
                }
        }
        return false;
    }
}
