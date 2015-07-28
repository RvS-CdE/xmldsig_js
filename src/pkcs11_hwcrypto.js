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
	var Base64Hash = payload.base64hash;
	var Type = payload.digest_alg;

        return window.hwcrypto.getCertificate({lang:defaults.lang})
                     .then(function(cert)
                               {
                               var hash = new Uint8Array(4);
                               return window.hwcrypto.sign(cert,
                                                           {type: Type, hex: atob(Base64Hash)},
                                                           {lang: defaults.lang});
                               },
                           function(error)
                               {
                               _log("E GetCertificate failed: ",error.message);
                               throw('signature_failed');
                               })
                     .then(function(signature) 
                               {
                               _log("Signature Successful",signature);
                               return signature
                               });
        }

    function _log()
        {
        if (params.log && window.console && window.console.log)
            window.console.log.apply(console,arguments)
        };
    })();
