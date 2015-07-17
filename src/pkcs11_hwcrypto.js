// xmldsig_js PKCS#11 services provider using the Estonian open-eid effort, hwcrypto.js (great job!)

(function()
    {
    var root = this,
        w    = window,
        defaults = {log : false,
                    backend : null},
        params = defaults;

    w.pkcs11_hwcrypto = {init   : init
                                ,set    : set_params
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

    function _log()
        {
        if (params.log && window.console && window.console.log)
            window.console.log.apply(console,arguments)
        };
    })();
