<?php

namespace Italia\SPIDAuth\SAML;

use DOMDocument;
use OneLogin\Saml2\AuthnRequest;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Settings;

class SPIDAuthnRequest extends AuthnRequest
{
    private string $spidRequest;

    public function __construct(Settings $settings, $forceAuthn = false, $isPassive = false, $setNameIdPolicy = true, $nameIdValueReq = null)
    {
        // SPID does not send a requested Subject, even if the caller supplies one.
        parent::__construct($settings, $forceAuthn, $isPassive, $setNameIdPolicy);

        $document = new DOMDocument();
        $document->loadXML(parent::getXML());
        $root = $document->documentElement;
        $root->removeAttribute('ProviderName');
        $root->setAttribute('AttributeConsumingServiceIndex', (string) $settings->getSPData()['attributeConsumingService']['index']);

        $issuer = $document->getElementsByTagNameNS(Constants::NS_SAML, 'Issuer')->item(0);
        $issuer->setAttribute('NameQualifier', $settings->getSPData()['entityId']);
        $issuer->setAttribute('Format', Constants::NAMEID_ENTITY);

        foreach ($document->getElementsByTagNameNS(Constants::NS_SAMLP, 'NameIDPolicy') as $policy) {
            $policy->removeAttribute('AllowCreate');
        }

        $this->spidRequest = $document->saveXML($root);
    }

    public function getXML()
    {
        return $this->spidRequest;
    }

    public function getRequest($deflate = null)
    {
        $deflate ??= $this->_settings->shouldCompressRequests();

        return base64_encode($deflate ? gzdeflate($this->spidRequest) : $this->spidRequest);
    }
}
