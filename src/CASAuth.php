<?php
// Imports
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\MediaWikiServices;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\Session\SessionManager;


class CASAuth extends PluggableAuth {

	/**
	 * @var LoggerInterface
	 */
	private $logger;

	public function authenticate( &$id, &$username, &$realname, &$email, &$errorMessage ) { 
	$this->logger = LoggerFactory::getInstance( 'PluggableAuth' );

        // Get config options
        $config = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'CASAuth' ); // Get the config
        $server = $config->get( 'CASServer' );
        $port = $config->get( 'CASPort' );
        $url = $config->get( 'CASUrl' );
        $version = $config->get( 'CASVersion' );
	$casFolder = $config->get( 'CASPhpPlugin' );
	$mailField = $config->get( 'CASMailField' );
        $mailExtension = $config->get ('CASMailExtension' );
	$nameField = $config->get( 'CASNameField' );

	require_once($casFolder."/CAS.php");
        phpCAS::client($version, $server, $port, $url, false);
        phpCAS::setSingleSignoutCallback('casSingleSignOut');
        phpCAS::setPostAuthenticateCallback('casPostAuth');
        phpCAS::setNoCasServerValidation();


        try {

            phpCAS::forceAuthentication();

	    $attributes = phpCAS::getAttributes();

	    $username = $this->casNameLookup(phpCAS::getUser());

            // casNameLookup() says name is invalid
            if (is_null($username)) {
	            // redirect user to the RestrictRedirect page
		    $errorMessage = "Invalid username";
                    return false;
            }


	    $id = null;
            // extract e-mail information
            if (phpCAS::hasAttribute($mailField)) 
                $email = phpCAS::getAttribute($mailField);
            else
                $email = $this->casEmailLookup(phpCAS::getUser(),$mailExtension);
	    // extract real name information
            if (phpCAS::hasAttribute($nameField)) 
                $realname = phpCAS::getAttribute($nameField);
	    else
                $realname = $this->casRealNameLookup(phpCAS::getUser());

            return true;

        }  catch ( Exception $e ) {
            // Log if something goes wrong
            $errorMessage = $e->__toString();
            return false;
	}
    }
    
    public function deauthenticate( User &$user ) {
	phpCAS::logout();
        return true;
    }
    
    public function saveExtraAttributes( $id ) {
     
    }

    function casNameLookup($username) {
	$preferUnderscore = true;

        $collisions = [ "/^_/", "/_$/", "/^ /", "/ $/", "/  /", "/__/", "/_ /", "/ _/", '/[\xA0\x{1680}\x{180E}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]+/u', '/\xE2\x80[\x8E\x8F\xAA-\xAE]/' ];
        $collisions[] = $preferUnderscore ? "/ /" : "/_/";

        foreach ($collisions as $collision) {
            if(preg_match($collision, $username)) {
            //# reject user name
                return null;
            }
        }

        //# test for invalid Unicode characters. ('/u' strips them out in PHP 5.2.x).
        $cleaned = preg_replace( '/_/u', '_', $username );
        if ($cleaned !== $username) { return null; }

        //# user name checks out
        return $username;
    }

    function casEmailLookup($username, $extension) {
        return $username."@".$extension;
    }

    function casRealNameLookup($username) {
        return $username;
    }
}
