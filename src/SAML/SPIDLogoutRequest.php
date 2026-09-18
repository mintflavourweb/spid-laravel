<?php

namespace Italia\SPIDAuth\SAML;

use DOMDocument;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Settings;

class SPIDLogoutRequest extends LogoutRequest
{
    public function __construct(Settings $settings, $request = null, $nameId = null, $sessionIndex = null, $nameIdFormat = null, $nameIdNameQualifier = null, $nameIdSPNameQualifier = null)
    {
        parent::__construct($settings, $request, $nameId, $sessionIndex, $nameIdFormat, $nameIdNameQualifier, $nameIdSPNameQualifier);

        if (null !== $request && '' !== $request) {
            return;
        }

        $document = new DOMDocument();
        $document->loadXML($this->_logoutRequest);
        $root = $document->documentElement;
        $root->setAttribute('Destination', $settings->getIdPData()['entityId']);

        $issuer = $document->getElementsByTagNameNS(Constants::NS_SAML, 'Issuer')->item(0);
        $issuer->setAttribute('NameQualifier', $settings->getSPData()['entityId']);
        $issuer->setAttribute('Format', Constants::NAMEID_ENTITY);

        $this->_logoutRequest = $document->saveXML($root);
    }
}
