<?php

namespace Italia\SPIDAuth\SAML;

use OneLogin\Saml2\LogoutResponse;

class SPIDLogoutResponse extends LogoutResponse
{
    public function getIssuer()
    {
        $issuer = parent::getIssuer();

        return null === $issuer ? null : trim($issuer);
    }
}
