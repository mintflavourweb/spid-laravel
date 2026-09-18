<?php

namespace Italia\SPIDAuth\SAML;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Settings;

class SPIDAuth extends Auth
{
    public function buildAuthnRequest(Settings $settings, $forceAuthn, $isPassive, $setNameIdPolicy, $nameIdValueReq = null)
    {
        return new SPIDAuthnRequest($settings, $forceAuthn, $isPassive, $setNameIdPolicy);
    }

    public function buildLogoutRequest(Settings $settings, $request = null, $nameId = null, $sessionIndex = null, $nameIdFormat = null, $nameIdNameQualifier = null, $nameIdSPNameQualifier = null)
    {
        return new SPIDLogoutRequest($settings, $request, $nameId, $sessionIndex, $nameIdFormat, $nameIdNameQualifier, $nameIdSPNameQualifier);
    }

    public function buildLogoutResponse(Settings $settings, $response = null)
    {
        return new SPIDLogoutResponse($settings, $response);
    }
}
