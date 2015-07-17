// See :
// https://github.com/RvS-CdE/xmldsig_js
//
// The object still needs a pkcs#11 services provider.

(function()
    {
    var root = this,
        w    = window,
        defaults = {log : false
                   ,pkcs11 : null
                   ,hashf  : 'SHA-256'
                   },
        params = defaults;

    w.xmldsig_js = {set  : set_params
                   ,sign : sign_text
                   };

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

    function sign_text(RawTxt)
        {
        var CleanText = RawTxt.replace(/\r/g,'');
        //var MsgDigest = 
        return new Promise(
            function(resolve,reject)
                {
                resolve(digest(CleanText));
                //reject({msg:'Nothing Yet'});
                });
        }

    function digest(Str)
        {
        var buffer = new TextEncoder("utf-8").encode(Str);
        return crypto.subtle.digest(defaults.hashf, buffer)
                            .then(function (hash) {
                                    return btoa(hex(hash));
                                    });
        }


    function hex(buffer) {
        var hexCodes = [];
        var view = new DataView(buffer);
        for (var i = 0; i < view.byteLength; i += 4) 
            {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            var value = view.getUint32(i)
            // toString(16) will give the hex representation of the number without padding
            var stringValue = value.toString(16)
            // We use concatenation and slice for padding
            var padding = '00000000'
            var paddedValue = (padding + stringValue).slice(-padding.length)
            hexCodes.push(paddedValue);
            }
        // Join all the hex strings into one
        return hexCodes.join("");
        }



    function _log()
        {
        if (params.log && window.console && window.console.log)
            window.console.log.apply(console,arguments)
        }

    })();
