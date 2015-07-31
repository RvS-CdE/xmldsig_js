// xmldsig_js PKCS#11 services provider using the Estonian open-eid effort, hwcrypto.js

(function()
    {
    var root = this,
        w    = window,
        defaults = {log : false,
                    lang : 'en',
                    backend : null},
        params = defaults;

    w.pkcs11_hwcrypto = {init   : init
                        ,set    : set_params
                        ,sign   : sign_promise
                        ,certificate : get_cert
                        };


    function init()
        {
        if (!window.hwcrypto)
            {
            _log("E hwcrypto not found. Has it been linked ?");
            throw(hwcrypto_unavailable);
            }

        if (!window.hwcrypto.use(defaults.backend))
                {
                _log('E hwcrypto failed to select backend');
                throw(hwcrypto_unavailable);
                }

        window.hwcrypto.debug().then(function(response) {_log("I ",response);});
        }

    function set_params(P)
        {
        if (P.backend != null && P.backend != "chrome" && P.backend != "npapi")
            throw "pcks11_bad_backend";

        for (var key in P)
            {
            if (P.hasOwnProperty(key))
                params[key] = P[key]
            }
        _log("I Parameters set, current config:",params);
        return this;
        }

    function sign_promise(payload)
        {
        var Type = payload.digest_alg;
        var cert = payload.cert;
        var HexHash = base64ToHex(payload.base64hash).toUpperCase();

        return window.hwcrypto.sign(cert,
                                    {type: Type, hex: HexHash},
                                    {lang: defaults.lang})
                              .then(function(signature)
                                    {
                                    _log("I Signature Successful",signature);
                                    return signature;
                                    });
        //return window.hwcrypto.getCertificate({lang:defaults.lang})
        //             .then(function(response)
        //                       {
        //                       var hash = new Uint8Array(4);
        //                       var cert = response;
        //                       var HexHash = base64ToHex(Base64Hash).toUpperCase();
        //                       _log('B64:',Base64Hash, 'Hex:', HexHash,'Type:',Type);
        //                       return window.hwcrypto.sign(cert,
        //                                                   {type: Type, hex: HexHash},
        //                                                   {lang: defaults.lang})
        //                                             .then(function(signature)
        //                                                   {
        //                                                   _log("Signature Successful",signature);
        //                                                   signature.key_hex = cert.hex;
        //                                                   return signature;
        //                                                   });
        //                       },
        //                   function(error)
        //                       {
        //                       _log("E GetCertificate failed: ",error.message);
        //                       throw('signature_failed');
        //                       });
        }

    function get_cert()
        {
        return window.hwcrypto.getCertificate({lang:defaults.lang})
                              .then(function(resp)
                                    {
                                    return {hex : resp.hex
                                           ,raw : resp};
                                    });
        }

    // Inspiration:
    // http://stackoverflow.com/questions/23190056/hex-to-base64-converter-for-javascript
    function base64ToHex(str) 
        {
        for (var i = 0, bin = atob(str.replace(/[ \r\n]+$/, "")), hex = []; i < bin.length; ++i) 
            {
            var tmp = bin.charCodeAt(i).toString(16);
            if (tmp.length === 1) tmp = "0" + tmp;
            hex[hex.length] = tmp;
            }
        return hex.join('');
        }

    function _log()
        {
        if (params.log && window.console && window.console.log)
            window.console.log.apply(console,arguments)
        };
    })();
