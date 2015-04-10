<?php
/**
 * SimpleTOTP Authentication Processing filter
 * 
 * SimpleTOTP is a SimpleSAMLphp auth processing filter that enables the use 
 *  of the Time-Based One-Time Password Algorithm (TOTP) as a second-factor 
 *  authentication mechanism on either an Identity Provider or Service Provider
 *  (...or both!).
 *
 * This has been tested with Google Authenticator on iOS and Android.
 *
 * <code>
 *  10 => array(
 *    'class' => 'simpletotp:2fa',
 *    'secret_attr' => 'totp_secret', //default
 *    'enforce_2fa' => false, //default
 *    'not_configured_url' => NULL,  //default
 *  ),
 * </code>
 *
 * @package simpleSAMLphp
 */

class sspmod_simpletotp_Auth_Process_2fa extends SimpleSAML_Auth_ProcessingFilter {
    /**
     * Value of the TOTP secret
     */
    private $secret_val = NULL;

    /**
     * Whether or not the user should be forced to use 2fa.
     *  If false, a user that does not have a TOTP secret will be able to continue
     *   authentication
     */
    private $enforce_2fa = false;

    /**
     * External URL to redirect user to if $enforce_2fa is true and they do not 
     *  have a TOTP attribute set.  If this attribute is NULL, the user will 
     *  be redirect to the internal error page.
     */
    private $not_configured_url = 'not_configured.php';

    /**
     * Base LinOTP authentication URL to authenticate against.
     */
    private $linotp_authentication_url = NULL;

    /**
     * Initialize the filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use
     */
    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('enforce_2fa', $config)) {
            $this->enforce_2fa = $config['enforce_2fa'];
            if (!is_bool($this->enforce_2fa)) {
                throw new Exception('Invalid attribute name given to simpletotp::2fa filter:
 enforce_2fa must be a boolean.');
            }
        }

        if (array_key_exists('not_configured_url', $config)) {
            $this->not_configured_url = $config['not_configured_url'];
            /*if (!is_string($config['not_configured_url'])) {
                throw new Exception('Invalid attribute value given to simpletotp::2fa filter:
 not_configured_url must be a string');
            }*/

            //validate URL to ensure it's we will be able to redirect to
            $this->not_configured_url = $config['not_configured_url'];
            SimpleSAML_Utilities::checkURLAllowed($config['not_configured_url']);
        }

        if (array_key_exists('linotp_authentication_url', $config)) {
            $this->linotp_authentication_url = $config['linotp_authentication_url'];
            if (!is_string($config['linotp_authentication_url'])) {
                throw new Exception('Invalid attribute value given to simpletotp::2fa filter:
 linotp_authentication_url must be a string');
            }
        }
    }

    /**
     * Apply SimpleTOTP 2fa filter
     *
     * @param array &$state  The current state
     */
    public function process(&$state) {
	$metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();
	$local_idp_entityid = $metadata->getMetaDataCurrentEntityID('saml20-idp-hosted');
	$local_idp_metadata = $metadata->getMetaData($local_idp_entityid, 'saml20-idp-hosted');

        assert('is_array($state)');
        assert('array_key_exists("Attributes", $state)');

        $attributes =& $state['Attributes'];

	if (!array_key_exists($local_idp_metadata['userid.attribute'], $attributes)) {
		throw new Exception('core:AttributeRealm: Missing UserID for this user. Please' .
			' check the \'userid.attribute\' option in the metadata against the' .
			' attributes provided by the authentication source.');
	}
        //as the attribute is configurable, we need to store it in a consistent location
        $state['2fa_secret'] = $this->secret_val;
	// URL to authenticate against
	$state['authentication_url'] = $this->linotp_authentication_url;

        //this means we have secret_val configured for this session, time to 2fa
        $id  = SimpleSAML_Auth_State::saveState($state, 'simpletotp:request');
        $url = SimpleSAML_Module::getModuleURL('simpletotp/authenticate.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));

        return;
    }
}
