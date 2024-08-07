/** jQuery Initialisation **/
(function ($) {
    $(function () {
        $(document).on('click', ".collapsible-header", function(){
            $(this).next('.collapsible-body').toggle(200);
        });
    }); // end of document ready
})(jQuery); // end of jQuery name space

function toggle_visibility(id) {
    const e = document.getElementById(id);
    e.classList.remove('may-be-hidden');
}

function hide(id) {
    const e = document.getElementById(id);
    e.classList.add('may-be-hidden');
}

/** WebSockets init**/
var arr = window.location.href.split('/');
var urlSockets = arr[0] + "//" + arr[2];
var socket;


/** base64url helper functions **/
/**
* Convert from a Base64URL-encoded string to an Array Buffer. Best used when converting a
* credential ID from a JSON string to an ArrayBuffer, like in allowCredentials or
* excludeCredentials
*
* Helper method to compliment `bufferToBase64URLString`
*/
function base64URLStringToBuffer(base64URLString) {
    // Convert from Base64URL to Base64
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    /**
     * Pad with '=' until it's a multiple of four
     * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
     * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
     * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
     * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
     */
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, '=');

    // Convert to a binary string
    const binary = atob(padded);

    // Convert binary string to buffer
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return buffer;
}

/**
* Convert the given array buffer into a Base64URL-encoded string. Ideal for converting various
* credential response ArrayBuffers to string for sending back to the server as JSON.
* 
* Helper method to compliment `base64URLStringToBuffer`
* 
* source: https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/src/helpers/bufferToBase64URLString.ts
*/
function bufferToBase64URLString(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';

    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }

    const base64String = btoa(str);

    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function toast(message, displayLength, className){
    Materialize.toast(message, displayLength, className);
    $('.toast').last()[0].setAttribute('role', 'alert');
}

/** Vue.JS **/

/** User **/
var PushMethod = Vue.extend({
    props: {
        'user': Object,
        'get_user': Function,
        'messages': Object,
        'activate': Function,
        'deactivate': Function,
        'switch_push_event': {}
    },
    created: function () {
        var self = this;
        socket = io.connect(urlSockets, {reconnect: true, path: "/sockets"});

        socket.on('userPushActivate', function () {
            self.activatePush();
        });

        socket.on('userPushActivateManager', function (data) {
            self.activatePush();
        });

    socket.on('userPushDeactivate', function () {
            self.deActivatePush();
        });
    },
    methods: {
        activatePush: function () {
            this.get_user(this.user.uid);
        },
    deActivatePush: function () {
            this.get_user(this.user.uid);
        }
    },
    template: '#push-method'
});

var BypassMethod = Vue.extend({
    props: {
        'user': Object,
        'generate_bypass': Function,
        'activate': Function,
        'deactivate': Function,
        'messages': Object
    },
    template: '#bypass-method'
});

const TotpMethod = Vue.extend({
    props: {
        'user': Object,
        'generate_totp': Function,
        'activate': Function,
        'deactivate': Function,
        'messages': Object,
        'formatApiUrl': Function,
    },
    methods: {
        validate: function() {
            const totpCode = this.user.methods.totp.validation_code;
            this.user.methods.totp.validation_code = '';
            $.ajax({
                method: "POST",
                url: this.formatApiUrl("/totp/activate/confirm/" + totpCode),
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        toast('Erreur, veuillez réessayer.', 3000, 'red darken-1');
                    } else {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.qrCode = '';
                        this.user.methods.totp.message = '';
                        toast('Code validé', 3000, 'green contrasted');
                    }
                }.bind(this),
                statusCode: {
                    401: function() {
                        toast(this.messages.api.methods.random_code.verify_code.wrong, 3000, 'red darken-1');
                    }.bind(this)
                },
                error: function (xhr, status, err) {
                    console.error("/api/totp/activate/confirm", status, err.toString());
                }.bind(this)
            });
        }
    },
    template: '#totp-method'
});

const WebAuthnMethod = Vue.extend({
    props: {
        'user': Object,
        'activate': Function,
        'deactivate': Function,
        'messages': Object,
        'formatApiUrl': Function,
    },
    data() {
        return {
            realData: { // example (will be override by mounted() )
                nonce: "",
                auths: [], // [{credentialID: "", credentialPublicKey: "", counter: 0, name: ""}],
                user_id: "",
                rp: { "name": "Univ", "id": "univ.fr" },
                pubKeyTypes: [{ "type": "public-key", "alg": -  7 }],
            },
            registrationInProgress: false,
        }
    },
    async mounted() {
        await this.fetchAuthData();

        if(this.realData.auths.length === 0) {
            this.generateWebauthn();
        }
    },
    computed: {
        descriptionMessage() {
            switch (this.realData.auths.length) {
                case 0:
                    return this.messages.api.methods.webauthn.no_authentificators;
                case 1:
                    return this.messages.api.methods.webauthn.single_auth;
                default:
                    return this.messages.api.methods.webauthn.nb_of_auths.replace('%NB%', this.realData.auths.length);
            }
        },
    },
    watch: {
        'user.uid': function(newUid, oldUid) {
            if (newUid !== oldUid) {
                this.fetchAuthData();
            }
        }
    },
    methods: {
        fetchAuthData: async function() {
            const res = await fetch(this.formatApiUrl("/generate/webauthn"), { method: "POST" });
            this.realData = await res.json()
            return this.realData;
        },
        getAuthById: function (id) {
            return this.realData.auths.find(authenticator => authenticator.credentialID === id);
        },
        renameAuthenticator: function(authCredID) {
            const auth = this.getAuthById(authCredID);
            const previousName = auth.name;
            return Swal.fire({ // https://sweetalert2.github.io/#configuration
                title: this.messages.api.action.rename + ' ' + previousName,
                input: "text",
                icon: "question",
                inputPlaceholder: this.messages.api.methods.webauthn.new_name,
                inputValue: previousName,
                customClass: { // https://sweetalert2.github.io/#customClass
                    input: "webauthn-factor-rename-input",
                    confirmButton: "waves-effect waves-light btn green contrasted",
                    cancelButton: "waves-effect waves-light btn red darken-1",
                },
                showCancelButton: true,
                allowOutsideClick: false,
                inputValidator: (newName) => {
                    if (!newName.trim()) {
                        return this.messages.error.webauthn.registration_failed;
                    }
                },
                showLoaderOnConfirm: true,
                preConfirm: async (newName) => {
                    if (previousName == newName) {
                        return;
                    }

                    let statusCode;

                    try {
                        const res = await fetch(this.formatApiUrl("/webauthn/auth/" + authCredID), {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json",
                            },
                            body: JSON.stringify({
                                name: newName
                            })
                        });
                        await this.fetchAuthData();
                        statusCode = res.status;
                    } catch (e) {
                        console.error(e);
                    }
                    
                    if (statusCode == 200) {
                        toast(this.messages.success.webauthn.renamed, 3000, 'green contrasted');
                    } else {
                        toast(this.messages.error.webauthn.generic, 3000, 'red darken-1');
                    }

                }
            });
        },

        deleteAuthenticator: function(authCredID) {
            // TODO : USE MESSAGES FILES FOR LOCALISATION
            const auth = this.getAuthById(authCredID);
            const name = auth.name;
            return Swal.fire({ // https://sweetalert2.github.io/#configuration
                title: this.messages.api.action.webauthn.confirm_delete.replace("%NAME%", name),
                icon: "warning",
                customClass: { // https://sweetalert2.github.io/#customClass
                    confirmButton: "waves-effect waves-light btn red darken-1",
                    cancelButton: "waves-effect waves-light btn green contrasted",
                },
                focusDeny: true,
                reverseButtons: true,
                showCancelButton: true,
                allowOutsideClick: true,
                showLoaderOnConfirm: true,
                preConfirm: async () => {
                    let statusCode;

                    try {
                        const res = await fetch(this.formatApiUrl("/webauthn/auth/" + authCredID), { method: "DELETE" });
                        await this.fetchAuthData();
                        statusCode = res.status;
                    } catch (e) {
                        console.error(e);
                    }

                    if (statusCode == 200) {
                        toast(this.messages.success.webauthn.deleted, 3000, 'green contrasted');
                    } else {
                        toast(this.messages.error.webauthn.delete_failed, 3000, 'red darken-1');
                    }

                }
            });
        },
        generateWebauthn: async function() {
            this.registrationInProgress = true;
            try {
                const data = await this.fetchAuthData();

                // arguments for the webauthn registration
                const publicKeyCredentialCreationOptions = {
                    challenge: base64URLStringToBuffer(data.nonce),
                    rp: data.rp,
                    rpId: data.rp.id,
                    user: {
                        id: Uint8Array.from(data.user_id),
                        name: `${this.user.uid}@${data.rp.id}`,
                        displayName: `${this.user.uid}`
                    },
                    // Spec recommends at least supporting these
                    pubKeyCredParams: data.pubKeyTypes,
                    // user has 3 * 60 seconds to register
                    timeout: 3 * 60000,
                    // leaks data about the user if in direct mode.
                    attestation: "none",
                    extensions: {
                        credProps: true,
                    },
                    authenticatorSelection: {
                        residentKey:"preferred",
                        requireResidentKey:false,
                        userVerification:"preferred"
                    },
                    // Don't register the same credentials twice
                    excludeCredentials: data.auths.map(a => ({id: base64URLStringToBuffer(a.credentialID), type: "public-key"})),
                };

                // register
                const credentials = await navigator.credentials.create({publicKey: publicKeyCredentialCreationOptions});

                // PublicKeyCredential can not be serialized
                // because it contains some ArrayBuffers, which
                // can not be serialized.
                // This just translates the buffer to its' 'safe'
                // version.
                // This is only for the REGISTRATION part
                // It is slightly different from what is
                // used for authentication
                const SerializePKC = PKC => {
                    return {
                        id: PKC.id,
                        type: PKC.type,
                        rawId: bufferToBase64URLString(PKC.rawId),
                        response: {
                            attestationObject: bufferToBase64URLString(PKC.response.attestationObject),
                            clientDataJSON: bufferToBase64URLString(PKC.response.clientDataJSON),
                        }
                    };
                }

                const verifyRes = await fetch(this.formatApiUrl("/webauthn/confirm_activate"), {
                    method: "POST",
                    headers: {
                        'Content-type': 'application/json'
                    },
                    body: JSON.stringify({
                        cred: SerializePKC(credentials),
                        cred_name: "Authenticator " + credentials.id.slice(-5),
                    }),
                });

                if(200 <= verifyRes.status && verifyRes.status < 300) {
                    const { registered } = await verifyRes.json();

                    if(registered) { // SUCCESS
                        await this.fetchAuthData();
                        await this.renameAuthenticator(credentials.id);
                    }
                    else {
                        toast(this.messages.error.webauthn.registration_failed, 3000, 'red darken-1');
                    }
                }
                else {
                    // timed out
                    if(verifyRes.status === 422) {
                        toast(this.messages.error.webauthn.timeout, 3000, 'red darken-1');
                    }
                    else {
                        toast(this.messages.error.webauthn.generic, 3000, 'red darken-1');
                    }
                }
            }
            catch(e) {
                // Already registered
                if(e.name === "InvalidStateError") {
                    toast(this.messages.error.webauthn.already_registered, 3000, 'red darken-1');
                }
                // user said no / something like that
                else if(e.name === "NotAllowedError") {
                    toast(this.messages.error.webauthn.user_declined, 3000, 'red darken-1');
                }
                else {
                    toast(this.messages.error.webauthn.generic, 3000, 'red darken-1');
                    console.error("/api/webauthn/confirm_activate", e);
                }
            } finally {
                this.registrationInProgress = false;
            }
        },
    },
    template: '#webauthn-method',
});

const RandomCodeMethod = Vue.extend({
    props: {
        'user': Object,
        'messages': Object,
        'activate': Function,
        'deactivate': Function,
        'formatApiUrl': Function,
    },
    methods: {
        saveTransport: function(transport) {
            var new_transport = document.getElementById(transport + '-input').value;
            var reg;
            if (transport == 'sms') reg = new RegExp("^((0[67](([.]|[-]|[ ])?[0-9]){8})|((00|[+])(([.]|[-]|[ ])?[0-9]){7,15}))$");
            else reg = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
            if (reg.test(new_transport)) {
                $.ajax({
                    method: 'GET',
                    url: this.formatApiUrl('/transport/' + transport + '/' + new_transport + "/test"),
                    dataType: 'json',
                    cache: false,
                    success: function(data) {
                        if (data.code != "Ok") {
                            toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                        }else {
                            const expected = data.otp;

                            const verifyCodeMessages = this.messages.api.methods.random_code.verify_code;

                            Swal.fire({ // https://sweetalert2.github.io/#configuration
                                title: verifyCodeMessages[transport].title,
                                html: verifyCodeMessages[transport].pre + new_transport + verifyCodeMessages[transport].post,
                                input: "number",
                                icon: "question",
                                // inputLabel: "Code",
                                inputPlaceholder: "000000",
                                customClass: { // https://sweetalert2.github.io/#customClass
                                    popup: "modal",
                                    container: "modal-content",
                                    input: "center-align",
                                    confirmButton: "waves-effect waves-light btn green contrasted",
                                    cancelButton: "waves-effect waves-light btn red darken-1",
                                },
                                showCancelButton: true,
                                allowOutsideClick: false,
                                inputValidator: input => {
                                    if(input != expected) {
                                        return verifyCodeMessages.wrong;
                                    }
                                },
                                showLoaderOnConfirm: true,
                                preConfirm: () => {
                                    return $.ajax({
                                        method: 'PUT',
                                        url: this.formatApiUrl('/transport/' + transport + '/' + new_transport),
                                        dataType: 'json',
                                        cache: false,
                                        success: function(data) {
                                            if (data.code != "Ok") {
                                                toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                                            } else {
                                                // equivalent to "this.user.transports[transport] = new_transport;", but allows new reactive property to be added dynamically
                                                Vue.set(this.user.transports, transport, new_transport);
                                                document.getElementById(transport + '-input').value = '';
                                                toast('Transport vérifié', 3000, 'green contrasted');
                                            }
                                        }.bind(this),
                                        error: function(xhr, status, err) {
                                            toast(err, 3000, 'red darken-1');
                                            console.error('/api/transport/' + transport + '/' + new_transport, status, err.toString());
                                        }.bind(this)
                                    });
                                }
                            });
                        }
                    }.bind(this),
                    error: function(xhr, status, err) {
                        toast(err, 3000, 'red darken-1');
                        console.error('/api/transport/' + transport + '/' + new_transport + "/test", status, err.toString());
                    }.bind(this)
                });
            }else toast('Format invalide.', 3000, 'red darken-1');
        },
        deleteTransport: function(transport) {
            var oldTransport = this.user.transports[transport];
            this.user.transports[transport]= null;
            $.ajax({
                method: 'DELETE',
                url: this.formatApiUrl('/transport/' + transport),
                dataType: 'json',
                cache: false,
                success: function(data) {
                    if (data.code != "Ok") this.user.transports[transport]= oldTransport;
                }.bind(this),
                error: function(xhr, status, err) {
                    this.user.transports[transport]= oldTransport;
                    toast(err, 3000, 'red darken-1');
                    console.error("/data/deactivate.json", status, err.toString());
                }.bind(this)
            });
        },
    },
    template: '#random_code-method'
});

const RandomCodeMailMethod = RandomCodeMethod.extend({
    template: '#random_code_mail-method'
});

var Esupnfc = Vue.extend({
template:'#esupnfc-method'
});

var UserDashboard = Vue.extend({
    props: {
        'messages': Object,
        'methods': Object,
        'user': Object,
        'currentmethod': String,
        'get_user': Function
    },
    components: {
        "push": PushMethod,
        "totp": TotpMethod,
        "bypass": BypassMethod,
        "webauthn": WebAuthnMethod,
        "random_code": RandomCodeMethod,
        "random_code_mail": RandomCodeMailMethod,
    "esupnfc":Esupnfc
    },
    template: "#user-dashboard",
    created: function () {
    },
    methods: {
        formatApiUrl: function(url) {
            return '/api' + url;
        },
        activate: function (method) {
            switch (method) {
                case 'push':
                    this.askPushActivation(method);
                    break;
                case 'bypass':
                    this.standardActivate(method);
                    this.generateBypass(function () {
                        this.user.methods.bypass.active = false;
                    });
                    break;
                case 'random_code':
                    this.standardActivate(method);
                    break;
                case 'random_code_mail':
                    this.standardActivate(method);
                    break;
                case 'totp':
                    this.generateTotp();
                    break;
                case 'webauthn':
                    this.standardActivate(method);
                    break;
                case 'esupnfc':
                    this.standardActivate(method);
                    break;
                default:
                    this.user.methods[method].active = true;
                    break;
            }
        },
        askPushActivation: function (method) {
            this.user.methods.push.askActivation = true;
            this.user.methods.push.active = true;
            //ajax
            $.ajax({
                method: "PUT",
                url: "/api/push/activate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") {
                        this.user.methods.push.activationCode = data.activationCode;
                        this.user.methods.push.qrCode = data.qrCode;
                        this.user.methods.push.api_url = data.api_url;
                    }else toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                }.bind(this),
                error: function (xhr, status, err) {
                    console.error("/api/push/activate", status, err.toString());
                }.bind(this)
            });
        },
        standardActivate: function (method) {
            $.ajax({
                method: "PUT",
                url: "/api/"+method+"/activate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
            this.user.methods[method].active = false;
                        toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else this.user.methods[method].active = true;
                }.bind(this),
                error: function (xhr, status, err) {
                    console.error("/api/"+method+"/activate", status, err.toString());
                }.bind(this)
            });
        },
        deactivate: function (method) {
            if (window.confirm(this.messages.api.action.confirm_deactivate)) {
                if (this.user.methods[method].askActivation)
                    this.user.methods[method].askActivation = false;
                $.ajax({
                    method: "PUT",
                    url: "/api/" + method + "/deactivate",
                    dataType: 'json',
                    cache: false,
                    success: function (data) {
                        if (data.code != "Ok") {
                            toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                        } else
                            this.user.methods[method].active = false;
                    }
                    .bind(this),
                    error: function (xhr, status, err) {
                        toast(err, 3000, 'red darken-1');
                        console.error("/api/" + method + "/deactivate", status, err.toString());
                    }
                    .bind(this)
                });
            }
        },
        generateBypassConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate))
                this.generateBypass();
        },
        generateTotpConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate))
                this.generateTotp();
        },
        generateBypass: function (onError) {
            $.ajax({
                method: "POST",
                url: "/api/generate/bypass",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") this.user.methods.bypass.codes = data.codes;
                    else if (typeof(onError) === "function") onError();
                }.bind(this),
                error: function (xhr, status, err) {
                    if (typeof(onError) === "function") onError();
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/generate/bypass", status, err.toString());
                }.bind(this)
            });
        },
        generateTotp: function (onError) {
            $.ajax({
                method: "POST",
                url: "/api/generate/totp?require_method_validation=true",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.message = data.message;
                        this.user.methods.totp.qrCode = data.qrCode;
                        this.user.methods.totp.uid = data.uid;
                    } else if (typeof(onError) === "function") onError();
                }.bind(this),
                error: function (xhr, status, err) {
                    if (typeof(onError) === "function") onError();
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/generate/totp", status, err.toString());
                }.bind(this)
            });
        }
    }
});

/** Manager **/
var UserView = Vue.extend({
    props: {
        'user': Object,
        'methods': Object,
        'messages': Object,
        "get_user": Function
    },
    components: {
        "push": PushMethod,
        "totp": TotpMethod,
        "bypass": BypassMethod,
        "webauthn": WebAuthnMethod,
        "random_code": RandomCodeMethod,
        "random_code_mail": RandomCodeMailMethod,
    "esupnfc":Esupnfc
    },
    data: function () {
        return {
            "switchPushEvent": MouseEvent
        }
    },
    template: '#user-view',
    methods: {
        formatApiUrl: function(url) {
            return '/api/admin' + url + '/' + this.user.uid;
        },
        activate: function (method) {
            switch (method) {
                case 'push':
                    this.askPushActivation(method);
                    break;
                case 'bypass':
                    this.standardActivate(method);
                    this.generateBypass(function () {
                        this.user.methods.bypass.active = false;
                    });
                    break;
                case 'webauthn':
                    this.standardActivate(method);
                    break;
                case 'random_code':
                    this.standardActivate(method);
                    break;
                case 'random_code_mail':
                    this.standardActivate(method);
                    break;
                case 'totp':
                    this.generateTotp();
                    break;
                case 'esupnfc':
                    this.standardActivate(method);
                    break;
                default:
                    /** **/
                    this.user.methods[method].active = true;
                    break;
            }
        },
        askPushActivation: function () {
            this.user.methods.push.askActivation = true;
            this.user.methods.push.active = true;
            //ajax
            $.ajax({
                method: "PUT",
                url: "/api/admin/" + this.user.uid + "/push/activate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") {
                        this.user.methods.push.activationCode = data.activationCode;
                        this.user.methods.push.qrCode = data.qrCode;
                        this.user.methods.push.api_url = data.api_url;
                    }else toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                }.bind(this),
                error: function (xhr, status, err) {
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + this.user.uid + "/push/activate", status, err.toString());
                }.bind(this)
            });
        },
        standardActivate: function (method) {
            $.ajax({
                method: "PUT",
                url: "/api/admin/" + this.user.uid + "/"+method+"/activate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        this.user.methods[method].active = false;
                        toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                    }else this.user.methods[method].active = true;
                }.bind(this),
                error: function (xhr, status, err) {
                    this.user.methods[method].active = false;
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + this.user.uid + "/"+method+"/activate", status, err.toString());
                }.bind(this)
            });
        },
        deactivate: function (method) {
            if (window.confirm(this.messages.api.action.confirm_deactivate)) {
                if (this.user.methods[method].askActivation)
                    this.user.methods[method].askActivation = false;
                $.ajax({
                    method: "PUT",
                    url: "/api/admin/" + this.user.uid + "/" + method + "/deactivate",
                    dataType: 'json',
                    cache: false,
                    success: function (data) {
                        if (data.code == "Ok")
                            this.user.methods[method].active = false;
                        else {
                            toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                            this.user.methods[method].active = true;
                        }
                    }
                    .bind(this),
                    error: function (xhr, status, err) {
                        this.user.methods[method].active = true;
                        toast(err, 3000, 'red darken-1');
                        console.error("/api/admin/" + this.user.uid + "/" + method + "/activate", status, err.toString());
                    }
                    .bind(this)
                });
            }
        },
        generateBypassConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate)) this.generateBypass();
        },
        generateTotpConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate)) this.generateTotp();
        },
        generateBypass: function (onError) {
            $.ajax({
                method: "POST",
                url: "/api/admin/generate/bypass/" + this.user.uid,
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") this.user.methods.bypass.codes = data.codes;
                    else if (typeof(onError) === "function") onError();
                }.bind(this),
                error: function (xhr, status, err) {
                    if (typeof(onError) === "function") onError();
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/generate/bypass/" + this.user.uid, status, err.toString());
                }.bind(this)
            });
        },
        generateTotp: function (onError) {
            $.ajax({
                method: "POST",
                url: "/api/admin/generate/totp/" + this.user.uid + "?require_method_validation=true",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.message = data.message;
                        this.user.methods.totp.qrCode = data.qrCode;
                        this.user.methods.totp.uid = data.uid;
                    } else if (typeof(onError) === "function") onError();
                }.bind(this),
                error: function (xhr, status, err) {
                    if (typeof(onError) === "function") onError();
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/generate/bypass/" + this.user.uid, status, err.toString());
                }.bind(this)
            });
        },
    }
});

var ManagerDashboard = Vue.extend({
    props: {
        'methods': Object,
        'messages': Object,
        //'show':Boolean,
    },
    components: {
        "user-view": UserView
    },
    data: function () {
        return {
            suggestions: [],
            user: {
                uid: String,
                methods: Object,
                transports: Object
            },
            uids: Array,
            isHidden: true,
            textButton: String,
        }
    },
    created: function () {
        this.getUsers();
    },
    updated: function () {
        this.getUsers();
    },
    methods: {
        isInArray: function(value, array) {
            return array.indexOf(value) > -1;
        },

        suggest: function (event) {
            this.suggestions = [];
            if (event.target.value !== "") {
                for (const uid in this.uids) {
                    this.isHidden= true;

                    if (this.uids[uid].includes(event.target.value)) {
                        this.suggestions.push(this.uids[uid]);
                    }
                }
            }
            if(this.isInArray($('#autocomplete-input').val(), this.suggestions)){
                this.isHidden= false;
                this.textButton = "chercher";
            }
            else{
                this.textButton = "ajouter";
                this.isHidden= false;
            }
            if ($('#autocomplete-input').val() === "")
                this.isHidden = true;
        },

        search: function (event) {
            if ($('#autocomplete-input').val() !== "" && this.suggestions.includes($('#autocomplete-input').val())) {
                this.getUser($('#autocomplete-input').val());
                $('#autocomplete-input').val('');
                this.isHidden = true;
                this.show = false;//
            }
        },

        addUser: function (event) {
            if ($('#autocomplete-input').val() !== "") {
                this.getUser($('#autocomplete-input').val());
                $('#autocomplete-input').val('');
                this.isHidden = true;
                this.getUsers();
                toast('utilisateur '+$('#autocomplete-input').val()+' ajouté avec succès', 3000, 'green contrasted');
            }
        },

        getUsers: function () {
            $.ajax({
                url: "/api/admin/users",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    this.setUsers(data);
                }.bind(this),
                error: function (xhr, status, err) {
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/users", status, err.toString());
                }.bind(this)
            });
        },

        setUsers: function (data) {
            this.uids = data.uids;
        },

        getUser: function (uid) {
            $.ajax({
                url: "/api/admin/user/" + uid,
                dataType: 'json',
                cache: false,
                success: function (data) {
                    data.uid = uid;
                    this.setUser(data);
                }.bind(this),
                error: function (xhr, status, err) {
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/user/" + uid, status, err.toString());
                }.bind(this)
            });
        },
        setUser: function (data) {
            this.user = {
                uid: data.uid,
                methods: data.user.methods,
                transports: data.user.transports
            }
        }
    },
    template: '#manager-dashboard'
});

/** Admin **/
var AdminDashboard = Vue.extend({
    props: {
        'messages': Object,
        'methods': Object
    },
    template: '#admin-dashboard',
    methods: {
        activate: function (event) {
            event.target.checked = true;
            $.ajax({
                method: "PUT",
                url: "/api/admin/" + event.target.name + "/activate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        event.target.checked = false;
                        toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else {
                        this.methods[event.target.name].activate = true;
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = false;
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + event.target.name + "/activate", status, err.toString());
                }.bind(this)
            });
        },
        deactivate: function (event) {
            event.target.checked = false;
            $.ajax({
                method: "PUT",
                url: "/api/admin/" + event.target.name + "/deactivate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        this.methods[event.target.name].activate = true;
                        toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else this.methods[event.target.name].activate = false;
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = true;
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + event.target.name + "/deactivate", status, err.toString());
                }.bind(this)
            });
        },
        activateTransport: function (method, transport) {
            event.target.checked = true;
            $.ajax({
                method: "PUT",
                url: "/api/admin/" + method + "/transport/" + transport + "/activate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        event.target.checked = false;
                        toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else {
                        this.methods[method].transports.push(transport);
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = false;
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + method + "/transport/" + transport + "/activate", status, err.toString());
                }.bind(this)
            });
        },
        deactivateTransport: function (method, transport) {
            event.target.checked = false;
            $.ajax({
                method: "PUT",
                url: "/api/admin/" + method + "/transport/" + transport + "/deactivate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        event.target.checked = true;
                        toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                    } else {
                        var index = this.methods[method].transports.indexOf(transport);
                        if (index > (-1)) this.methods[method].transports.splice(index, 1);
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = true;
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + method + "/transport/" + transport + "/deactivate", status, err.toString());
                }.bind(this)
            });
        },
    }
});

/** Admin **/
var Home = Vue.extend({
    props: {
        messages: Object,
        'methods': Object,
    },
    methods: {
        navigate: function (name) {
            document.getElementById(name).click();
        },
    },
    template: '#home-dashboard'
});

/** Main **/
var app = new Vue({
    el: '#app',
    components: {
        "home": Home,
        "preferences": UserDashboard,
        "manager": ManagerDashboard,
        "admin": AdminDashboard
    },
    data: {
        pageTitle: 'Accueil',
        currentView: 'home',
        currentMethod: '',
        methods: {},
        user: {
            uid: '',
            methods: {},
            transports: {}
        },
        users_methods:{},
        uids: [],
        messages: {}
    },
    created: function () {
        this.getMessages();
        this.getUser();
        this.getMethods();
    },
    methods: {
        cleanMethods: function () {
            for (const method in this.methods) {
                if (method[0] == '_') delete this.methods[method];
                else {
                    this.methods[method].name = method;
                    this.methods[method].authorize=this.is_authorized(method);
                    if (this.messages.api) {
                        if (this.messages.api.methods[method]) this.methods[method].label = this.messages.api.methods[method].name;
                    }
                }
            }

        },

        navigate: function (event) {
            if (event.target.name == "manager") {
                this.pageTitle = event.target.text;
                this.currentView = 'manager';
            } else if (event.target.name == "admin") {
                this.currentView = 'admin';
                this.pageTitle = event.target.text;
            } else if (event.target.name == "home") {
                this.currentView = 'home';
                this.pageTitle = event.target.text;
            } else {
                this.pageTitle = "Préférences";
                this.currentMethod = event.target.name;
                this.currentView = 'preferences';
            }
            $('a').parent().removeClass('active');
                $('#' + event.target.name).parent().addClass('active');
                if (document.getElementById("sidenav-overlay"))$('#navButton').click();
            this.getUser();
        },

        getUser: function () {
            $.ajax({
                url: "/api/user",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    this.setUser(data);
                }.bind(this),
                error: function (xhr, status, err) {
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/user", status, err.toString());
                }.bind(this)
            });
        },

        setUser: function (data) {
            this.user.uid = data.uid;
            this.user.methods = data.user.methods;
            this.user.transports = data.user.transports;
        },
        getMethods: function () {
            $.ajax({
                url: "/api/methods",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    $.ajax({
                        url: "/manager/users_methods",
                        dataType: 'json',
                        cache: false,
                        success: function (users_methods) {
                            this.users_methods=users_methods;
                            this.setMethods(data);
                        }.bind(this),
                        error: function (xhr, status, err) {
                            toast(err, 3000, 'red darken-1');
                            console.error("/manager/users_methods", status, err.toString());
                        }.bind(this)
                    });
                }.bind(this),
                error: function (xhr, status, err) {
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/methods", status, err.toString());
                }.bind(this)
            });
        },
        setMethods: function (data) {
            this.methods = data.methods;
            this.cleanMethods();
        },
        getMessages: function (language) {
            var query = '';
            if(language)query="/"+language;
            $.ajax({
                url: "/api/messages" + query,
                dataType: 'json',
                cache: false,
                success: function (data) {
                    this.setMessages(data);
                }.bind(this),
                error: function (xhr, status, err) {
                    toast(err, 3000, 'red darken-1');
                    console.error("/api/messages", status, err.toString());
                }.bind(this)
            });
        },
        setMessages: function (data) {
            this.messages = data;
            this.cleanMethods();
        },
    checkAcl: function (method, acl) {
        var result = false;
        var not = "";
        if (acl == "deny") {
            result = true;
            not = "not ";
        }
        if (this.users_methods[method][acl] && this.users_methods.user.attributes) {
            for (const attr in this.users_methods[method][acl]) {
                //console.debug("this.users_methods["+method+"]["+acl+"]: "+JSON.stringify(this.users_methods[method][acl]));
                //console.debug("User: "+JSON.stringify(this.users_methods.user));
                if (this.users_methods.user.attributes[attr]) {
                    for (const valueAttr of this.users_methods[method][acl][attr]) {
                        if (this.users_methods.user.attributes[attr].includes(valueAttr)) {
                            //console.debug("{"+method+"} method is "+not+"displayed because user attribute {"+attr+"} contains {"+valueAttr+"}");
                            return !result;
                        }
                    }
                }
            }
        }
        return result;
    },
    is_authorized: function (method) {
        var result = true; //par défaut, la méthode est autorisée
        if (this.users_methods && this.users_methods[method]) {
            for (const acl in this.users_methods[method]) { //pour une méthode, la priorité porte sur le dernier acl [allow|deny].
                result = this.checkAcl(method, acl);
            }
        }
        return result;
    }
  }
})
