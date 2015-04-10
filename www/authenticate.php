<?php
/**
 * SimpleTOTP Authenticate script
 *
 * This script displays a page to the user, which requests that they
 * submit the response from their TOTP generator.
 *
 * @package simpleSAMLphp
 */
 $globalConfig = SimpleSAML_Configuration::getInstance();

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML_Error_BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];

$sid = SimpleSAML_Utilities::parseStateID($id);
if (!is_null($sid['url'])) {
    SimpleSAML_Utilities::checkURLAllowed($sid['url']);
}

$state = SimpleSAML_Auth_State::loadState($id, 'simpletotp:request');
$displayed_error = NULL;

//if code is set, user has posted back to this page with a guess
if (array_key_exists('code', $_REQUEST)) {
    if (!ctype_digit($_REQUEST['code'])) {
        $displayed_error = "A valid TOTP token consists of only numeric values.";
    } else {
        //check if code is valid
	$request = $state['authentication_url'] . '/validate/check?pass=' .
		$_REQUEST['code'] . '&user=' . $state['UserID'];
	$ch = curl_init($request);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	// Blindly accept certificate
	// TODO make this not awful
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	$r = curl_exec($ch);
	curl_close($ch);
	if ($r == NULL) {
		throw new Exception("There was an issue with the server. Please " .
			"contact your helpdesk administrator.");
	}
	$auth_response = json_decode($r);
	print_r($auth_response->{'result'}->{'status'});
	if ($_REQUEST['code'] == $auth_response->{'result'}->{'value'}) {
		SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
	} else {
            $displayed_error = "You have entered the incorrect TOTP token.";
        }
    }
}

// populate values for template
$t = new SimpleSAML_XHTML_Template($globalConfig, 'simpletotp:authenticate.php');
$t->data['formData'] = array('StateId' => $id);
$t->data['formPost'] = SimpleSAML_Module::getModuleURL('simpletotp/authenticate.php');
$t->data['userError'] = $displayed_error;
$t->show();
