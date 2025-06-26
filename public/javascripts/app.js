/** jQuery Initialisation **/
(function ($) {
    $(function () {
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

async function fetchApi({
    uri,
    method = "GET",
    headers = { "Content-Type": "application/json", 'Accept': 'application/json' },
    body,
    onSuccess, // res => {} (executed if status >= 200 && < 300)
    onStatus = {}, // {status: (res) => {}}
}) {
    try {
        const res = await fetch(uri, { method, headers, body });
        res.data = await res.json();

        if (res.ok) {
            await onSuccess?.(res);
        } else if (res.data?.code === 'REDIRECT') {
            window.alert("Session expirée. Veuillez vous reconnecter.")
            return document.location.replace(res.data.path); // redirect to res.data.path (/login or /forbidden)
        } else if (onStatus[res.status]) {
            await onStatus[res.status](res);
        } else {
            const err = new Error(JSON.stringify({ status: res.status, data: res.data }));
            err.res = res;
            throw err;
        }
        return res;
    } catch (err) {
        console.error(err.res?.url || uri, err);
        throw err;
    }
}

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

function getImgWithAltText({ qrCodeImg, qrCodeSrc, alt = "QR code Esup Auth" }) {
    if (!qrCodeSrc) {
        if (qrCodeImg) {
            // extract src from img
            qrCodeSrc = new DOMParser().parseFromString(qrCodeImg, 'text/html').querySelector('img')?.src;
        } else {
            return "";
        }
    }
    return `<img src="${qrCodeSrc}" alt="${alt}">`;
}

function toast({ message, displayLength = 9000, className }) {
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
        'infos': Object,
        'activate': Function,
        'deactivate': Function,
        'switch_push_event': {}
    },
    created: function() {
        socket = io.connect(urlSockets, { reconnect: true, path: "/sockets" });

        socket.on('userPushActivate', () => {
            this.activatePush();
        });

        socket.on('userPushActivateManager', () => {
            this.activatePush();
        });

        socket.on('userPushDeactivate', () => {
            this.deActivatePush();
        });
    },
    methods: {
        activatePush: function() {
            this.setActivePush(true);
        },
        deActivatePush: function() {
            this.setActivePush(false);
        },
        setActivePush: async function(active) {
            // Temporarily set the opposite value, to help VueJs detect the change #33
            this.$set(this.user.methods.push, "active", !active);
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
        'messages': Object,
        'infos': Object,
    },
    computed: {
        generationDateString() {
            const date = new Date(this.user.methods.bypass.generation_date);
            return date.toLocaleDateString(this.infos.lang || "en", dateTimeFormatOptions)
        },
    },
    template: '#bypass-method'
});

const dateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
};

const PasscodeGridMethod = Vue.extend({
    props: {
        'user': Object,
        'generate_passcode_grid': Function,
        'activate': Function,
        'deactivate': Function,
        'messages': Object,
        'infos': Object,
    },
    computed: {
        generationDateString() {
            const date = new Date(this.user.methods.passcode_grid.generation_date);
            return date.toLocaleDateString(this.infos.lang || "en", dateTimeFormatOptions)
        },
    },
    template: '#passcode_grid-method'
});

const TotpMethod = Vue.extend({
    props: {
        'user': Object,
        'generate_totp': Function,
        'activate': Function,
        'deactivate': Function,
        'messages': Object,
        'infos': Object,
        'formatApiUri': Function,
    },
    methods: {
        validate: function() {
            const totpCode = this.user.methods.totp.validation_code;
            this.user.methods.totp.validation_code = '';
            return fetchApi({
                method: "POST",
                uri: this.formatApiUri("/totp/activate/confirm/" + totpCode),
                onSuccess: res => {
                    if (res.data.code != "Ok") {
                        toast({ message: 'Erreur, veuillez réessayer.', className: 'red darken-1' });
                    } else {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.qrCode = '';
                        this.user.methods.totp.message = '';
                        toast({ message: 'Code validé', className: 'green contrasted' });
                    }
                },
                onStatus: {
                    401: res => {
                        toast({ message: this.messages.api.methods.random_code.verify_code.wrong, className: 'red darken-1' });
                    }
                }
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
        'infos': Object,
        'formatApiUri': Function,
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
            const res = await fetchApi({
                method: "POST",
                uri: this.formatApiUri("/generate/webauthn"),
            });
            this.realData = res.data;
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
                        const res = await fetchApi({
                            method: "POST",
                            uri: this.formatApiUri("/webauthn/auth/" + authCredID),
                            body: JSON.stringify({
                                name: newName
                            }),
                        });
                        await this.fetchAuthData();
                        statusCode = res.status;
                    } catch (e) {
                        console.error(e);
                    }

                    if (statusCode == 200) {
                        toast({ message: this.messages.success.webauthn.renamed, className: 'green contrasted' });
                    } else {
                        toast({ message: this.messages.error.webauthn.generic, className: 'red darken-1' });
                    }

                }
            });
        },

        deleteAuthenticator: function(authCredID) {
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
                        const res = await fetchApi({
                            method: "DELETE",
                            uri: this.formatApiUri("/webauthn/auth/" + authCredID),
                        });
                        await this.fetchAuthData();
                        statusCode = res.status;
                    } catch (e) {
                        console.error(e);
                    }

                    if (statusCode == 200) {
                        toast({ message: this.messages.success.webauthn.deleted, className: 'green contrasted' });
                    } else {
                        toast({ message: this.messages.error.webauthn.delete_failed, className: 'red darken-1' });
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

                await fetchApi({
                    method: "POST",
                    uri: this.formatApiUri("/webauthn/confirm_activate"),
                    body: JSON.stringify({
                        cred: SerializePKC(credentials),
                        cred_name: "Authenticator " + credentials.id.slice(-5),
                    }),
                    onSuccess: async res => {
                        if (res.data.registered) { // SUCCESS
                            await this.fetchAuthData();
                            await this.renameAuthenticator(credentials.id);
                        }
                        else {
                            toast({ message: this.messages.error.webauthn.registration_failed, className: 'red darken-1' });
                        }
                    },
                    onStatus: {422: () => {
                        toast({ message: this.messages.error.webauthn.timeout, className: 'red darken-1' });
                    }},
                });
            }
            catch(e) {
                // Already registered
                if(e.name === "InvalidStateError") {
                    toast({ message: this.messages.error.webauthn.already_registered, className: 'red darken-1' });
                }
                // user said no / something like that
                else if(e.name === "NotAllowedError") {
                    toast({ message: this.messages.error.webauthn.user_declined, className: 'red darken-1' });
                }
                else {
                    toast({ message: this.messages.error.webauthn.generic, className: 'red darken-1' });
                    console.error("/api/webauthn/confirm_activate", e);
                }
            } finally {
                this.registrationInProgress = false;
            }
        },
    },
    template: '#webauthn-method',
});

Vue.component('transport-form', {
    props: {
        'user': Object,
        'messages': Object,
        'infos': Object,
        'transport': String,
        'inputType': String,
        'saveTransport': Function,
        'deleteTransport': Function,
    },
    template: '#transport_form'
});

const RandomCodeMethod = Vue.extend({
    props: {
        'user': Object,
        'messages': Object,
        'infos': Object,
        'activate': Function,
        'deactivate': Function,
        'formatApiUri': Function,
    },
    methods: {
        saveTransport: async function(transport) {
            const new_transport = document.getElementById(transport + '-input').value.trim();
            try {
                const res = await fetchApi({
                    method: "GET",
                    uri: this.formatApiUri('/transport/' + transport + '/' + new_transport + "/test"),
                });
                const data = res.data;
                if (data.code != "Ok") {
                    toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
                } else {
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
                            if (input != expected) {
                                return verifyCodeMessages.wrong;
                            }
                        },
                        showLoaderOnConfirm: true,
                        preConfirm: async () => {
                            const res = await fetchApi({
                                method: "PUT",
                                uri: this.formatApiUri('/transport/' + transport + '/' + new_transport),
                            });
                            const data = res.data;
                            if (data.code != "Ok") {
                                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
                            } else {
                                // equivalent to "this.user.transports[transport] = new_transport;", but allows new reactive property to be added dynamically
                                Vue.set(this.user.transports, transport, new_transport);
                                document.getElementById(transport + '-input').value = '';
                                toast({ message: 'Transport vérifié', className: 'green contrasted' });
                            }
                        }
                    });
                }


            } catch (err) {
                toast({ message: err, className: 'red darken-1' });
            };
        },
        deleteTransport: function(transport) {
            var oldTransport = this.user.transports[transport];
            this.user.transports[transport] = null;

            return fetchApi({
                method: "DELETE",
                uri: this.formatApiUri('/transport/' + transport),
                onSuccess: res => {
                    if (res.data.code != "Ok") {
                        throw new Error(JSON.stringify({ code: res.data.code }));
                    }
                },
            }).catch(err => {
                this.user.transports[transport] = oldTransport;
                toast({ message: err, className: 'red darken-1' });
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
        'infos': Object,
        'methods': Object,
        'user': Object,
        'currentmethod': String,
        'get_user': Function
    },
    components: {
        "push": PushMethod,
        "totp": TotpMethod,
        "bypass": BypassMethod,
        "passcode_grid": PasscodeGridMethod,
        "webauthn": WebAuthnMethod,
        "random_code": RandomCodeMethod,
        "random_code_mail": RandomCodeMailMethod,
    "esupnfc":Esupnfc
    },
    template: "#user-dashboard",
    created: function () {
    },
    methods: {
        formatApiUri: function(url) {
            return '/api' + url;
        },
        activate: function (method) {
            switch (method) {
                case 'push':
                    this.askPushActivation();
                    break;
                case 'bypass':
                    this.standardActivate(method);
                    this.generateBypass()
                        .catch(err => {
                            this.user.methods.bypass.active = false;
                        });
                    break;
                case 'passcode_grid':
                    this.standardActivate(method).then(res => this.setPasscodeGrid(res.data));
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
        askPushActivation: function() {
            this.user.methods.push.askActivation = true;
            this.user.methods.push.active = true;

            return fetchApi({
                method: "PUT",
                uri: "/api/push/activate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.push.activationCode = data.activationCode;
                        this.user.methods.push.qrCode = getImgWithAltText({ qrCodeImg: data.qrCode, qrCodeSrc: data.qrCodeSrc });
                        this.user.methods.push.api_url = this.infos.api_url;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        standardActivate: function(method) {
            return fetchApi({
                method: "PUT",
                uri: "/api/" + method + "/activate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods[method].active = true;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        deactivate: function(method) {
            if (window.confirm(this.messages.api.action.confirm_deactivate)) {
                if (this.user.methods[method].askActivation) {
                    this.user.methods[method].askActivation = false;
                }

                return fetchApi({
                    method: "PUT",
                    uri: "/api/" + method + "/deactivate",
                    onSuccess: res => {
                        const data = res.data;
                        if (data.code == "Ok") {
                            this.user.methods[method].active = false;
                        } else {
                            console.error(JSON.stringify({ code: data.code }));
                            throw new Error("Erreur interne, veuillez réessayer plus tard.");
                        }
                    },
                }).catch(err => {
                    this.user.methods[method].active = true;
                    toast({ message: err, className: 'red darken-1' });
                });
            }
        },
        generateBypassConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate))
                this.generateBypass();
        },
        generatePasscodeGridConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate))
                this.generatePasscodeGrid();
        },
        generateTotpConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate))
                this.generateTotp();
        },
        generateBypass: function() {
            return fetchApi({
                method: "POST",
                uri: "/api/generate/bypass",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.bypass.codes = data.codes;
                        this.user.methods.bypass.generation_date = data.generation_date;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
                throw err;
            });
        },
        generatePasscodeGrid: function() {
            return fetchApi({
                method: "POST",
                uri: "/api/generate/passcode_grid",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.setPasscodeGrid(data);
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
                throw err;
            });
        },
        setPasscodeGrid: function(data) {
            this.$set(this.user.methods.passcode_grid, "grid", data.grid);
            this.$set(this.user.methods.passcode_grid, "generation_date", data.generation_date);
        },
        generateTotp: function() {
            return fetchApi({
                method: "POST",
                uri: "/api/generate/totp?require_method_validation=true",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.message = data.message;
                        this.user.methods.totp.qrCode = getImgWithAltText({ qrCodeImg: data.qrCode, qrCodeSrc: data.qrCodeSrc });
                        this.user.methods.totp.uid = this.user.uid;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
                throw err;
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
        'infos': Object,
        "get_user": Function
    },
    components: {
        "push": PushMethod,
        "totp": TotpMethod,
        "bypass": BypassMethod,
        "passcode_grid": PasscodeGridMethod,
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
        formatApiUri: function(url) {
            return '/api/admin' + url + '/' + this.user.uid;
        },
        activate: function (method) {
            switch (method) {
                case 'push':
                    this.askPushActivation();
                    break;
                case 'bypass':
                    this.standardActivate(method);
                    this.generateBypass()
                        .catch(err => {
                            this.user.methods.bypass.active = false;
                        });
                    break;
                case 'passcode_grid':
                    this.standardActivate(method).then(res => this.setPasscodeGrid(res.data));
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

            return fetchApi({
                method: "PUT",
                uri: "/api/admin/" + this.user.uid + "/push/activate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.push.activationCode = data.activationCode;
                        this.user.methods.push.qrCode = getImgWithAltText({ qrCodeImg: data.qrCode, qrCodeSrc: data.qrCodeSrc });
                        this.user.methods.push.api_url = this.infos.api_url;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        standardActivate: function(method) {
            return fetchApi({
                method: "PUT",
                uri: "/api/admin/" + this.user.uid + "/" + method + "/activate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods[method].active = true;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        deactivate: function(method) {
            if (window.confirm(this.messages.api.action.confirm_deactivate)) {
                if (this.user.methods[method].askActivation)
                    this.user.methods[method].askActivation = false;

                return fetchApi({
                    method: "PUT",
                    uri: "/api/admin/" + this.user.uid + "/" + method + "/deactivate",
                    onSuccess: res => {
                        const data = res.data;
                        if (data.code == "Ok") {
                            this.user.methods[method].active = false;
                        } else {
                            console.error(JSON.stringify({ code: data.code }));
                            throw new Error("Erreur interne, veuillez réessayer plus tard.");
                        }
                    },
                }).catch(err => {
                    this.user.methods[method].active = true;
                    toast({ message: err, className: 'red darken-1' });
                });
            }
        },
        generateBypassConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate)) this.generateBypass();
        },
        generatePasscodeGridConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate)) this.generatePasscodeGrid();
        },
        generateTotpConfirm : function(){
            if (window.confirm(this.messages.api.action.confirm_generate)) this.generateTotp();
        },
        generateBypass: function() {
            return fetchApi({
                method: "POST",
                uri: "/api/admin/generate/bypass/" + this.user.uid,
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.bypass.codes = data.codes;
                        this.user.methods.bypass.generation_date = data.generation_date;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
                throw err;
            });
        },
        generatePasscodeGrid: function() {
            return fetchApi({
                method: "POST",
                uri: "/api/admin/generate/passcode_grid/" + this.user.uid,
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.setPasscodeGrid(data);
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
                throw err;
            });
        },
        setPasscodeGrid: function(data) {
            this.$set(this.user.methods.passcode_grid, "grid", data.grid);
            this.$set(this.user.methods.passcode_grid, "generation_date", data.generation_date);
        },
        generateTotp: function() {
            return fetchApi({
                method: "POST",
                uri: "/api/admin/generate/totp/" + this.user.uid + "?require_method_validation=true",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.message = data.message;
                        this.user.methods.totp.qrCode = getImgWithAltText({ qrCodeImg: data.qrCode, qrCodeSrc: data.qrCodeSrc });
                        this.user.methods.totp.uid = this.user.uid;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
                throw err;
            });
        },
    }
});

var ManagerDashboard = Vue.extend({
    props: {
        'methods': Object,
        'messages': Object,
        'infos': Object,
    },
    components: {
        "user-view": UserView
    },
    data: function () {
        return {
            user: {
                uid: String,
                methods: Object,
                transports: Object
            },
            uids: [],
            requestedUid: '',
        }
    },
    computed: {
        suggestions() {
            return this.uids.filter(uid => uid.toLowerCase().includes(this.requestedUid.toLowerCase()));
        },
        requestedUidExists() {
          return this.suggestions.includes(this.requestedUid);
        },
    },
    created: function () {
        if (this.uids?.length) {
            return;
        }
        return fetchApi({
            method: "GET",
            uri: "/api/admin/users",
            onSuccess: res => {
                this.uids = res.data.uids;
            },
        }).catch(err => {
            toast(err, 3000, 'red darken-1');
        });
    },
    mounted: async function() {
        const url = new URL(location);
        const user = url.searchParams.get('user');
        if (user) { // if url contains ?user=xxx
            await this.$nextTick();
            await this.getUser(user); // display user xxx
            await this.$nextTick();
            url.searchParams.set('user', '');
            history.pushState({}, '', url); // and remove xxx from current url
        }
    },
    methods: {
        search: function () {
            if (this.requestedUid) {
                this.getUser(this.requestedUid);
                if(!this.requestedUidExists) {
                    this.uids.push.push(this.requestedUid);
                    toast({ message: 'utilisateur ' + this.requestedUid + ' ajouté avec succès', className: 'green contrasted' });
                }
                this.requestedUid = '';
            }
        },

        getUser: function(uid) {
            return fetchApi({
                method: "GET",
                uri: "/api/admin/user/" + uid,
                onSuccess: res => {
                    const data = res.data;
                    data.uid = uid;
                    this.setUser(data);
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
            });
        },
        setUser: function(data) {
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
        'infos': Object,
        'methods': Object
    },
    template: '#admin-dashboard',
    methods: {
        activate: function(event) {
            event.target.checked = true;
            return fetchApi({
                method: "PUT",
                uri: "/api/admin/" + event.target.name + "/activate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.methods[event.target.name].activate = true;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                event.target.checked = false;
                this.methods[event.target.name].activate = false;
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        deactivate: function(event) {
            event.target.checked = false;
            return fetchApi({
                method: "PUT",
                uri: "/api/admin/" + event.target.name + "/deactivate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.methods[event.target.name].activate = false;
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                event.target.checked = true;
                this.methods[event.target.name].activate = true;
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        activateTransport: function(method, transport) {
            return fetchApi({
                method: "PUT",
                uri: "/api/admin/" + method + "/transport/" + transport + "/activate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.methods[method].transports.push(transport);
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        deactivateTransport: function(method, transport) {
            return fetchApi({
                method: "PUT",
                uri: "/api/admin/" + method + "/transport/" + transport + "/deactivate",
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        const index = this.methods[method].transports.indexOf(transport);
                        if (index > -1) {
                            this.methods[method].transports.splice(index, 1);
                        }
                    } else {
                        throw new Error(JSON.stringify({ code: data.code }));
                    }
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
    }
});

/** Stats  **/
var StatsDashboard = Vue.extend({
    props: {
        messages: Object,
    },
    data() {
        return {
            data: {},
            loading: false,
            chart: null,
        };
    },
    methods: {
        fetchStats() {
            this.loading = true;
            fetchApi({
                method: 'GET',
                uri: '/api/admin/stats',
                onSuccess: res => {
                    this.data = res.data;
                    this.loading = false;
                    this.$nextTick(() => {
                        this.renderChart(); // appel une fois le DOM mis à jour
                    });
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        renderChart() {

            const totalUsers = this.data.totalUsers;
            const totalMfaUsers = this.data.totalMfaUsers;

            if (this.chart) {
                this.chart.destroy(); // évite les superpositions
            }

            const ctx = document.getElementById('statsChartMfaMethods').getContext('2d');

            const methods = this.data.methods;

            const sorted = Object.entries(methods)
                .sort(([, a], [, b]) => b - a); // tri décroissant

            const labels = sorted.map(([method]) => this.messages.api.methods[method]?.name || method);
            const activated = sorted.map(([, count]) => count);
            const notActivated = activated.map(count => totalMfaUsers - count);
            const title = this.messages.stats.chart_title
                .replace("%NB_USERS_MFA%", totalMfaUsers)
                .replace("%NB_USERS%", totalUsers)
                .replace("%PERCENT_USERS_MFA%", ((totalMfaUsers / totalUsers) * 100).toFixed(1));

            this.chart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels,
                    datasets: [
                        {
                            label: this.messages.stats.methods_activated,
                            data: activated,
                            backgroundColor: '#42A5F5',
                        },
                        {
                            label: this.messages.stats.methods_deactivated,
                            data: notActivated,
                            backgroundColor: '#B0BEC5',
                        }
                    ],
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: title,
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const total = activated[context.dataIndex] + notActivated[context.dataIndex];
                                    const percent = ((context.raw / total) * 100).toFixed(1);
                                    return `${context.dataset.label}: ${context.raw} (${percent}%)`;
                                }
                            }
                        },
                        datalabels: {
                            anchor: 'center',
                            align: 'center',
                            formatter: (value, context) => {
                                const total = activated[context.dataIndex] + notActivated[context.dataIndex];
                                const percent = ((value / total) * 100).toFixed(1);
                                return `${percent}%`;
                            },
                            color: '#fff',
                            font: {
                                weight: 'bold'
                            }
                        }
                    },
                    scales: {
                        x: {
                            stacked: true,
                            beginAtZero: true,
                            max: totalMfaUsers
                        },
                        y: {
                            stacked: true
                        }
                    }
                },
                plugins: [ChartDataLabels]
            });
        }
    },
    mounted() {
        this.fetchStats();
    },
    template: '#stats-dashboard',
});


/** Admin **/
var Home = Vue.extend({
    props: {
        messages: Object,
        'infos': Object,
        'methods': Object,
        'user': Object,
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
        "admin": AdminDashboard,
        "stats": StatsDashboard
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
        messages: {},
        infos: {},
    },
    created: async function() {
        const messagesPromise = this.getMessages();
        this.getMethods();
        await this.getInfos();
        this.getUser();

        // wait for the #home button, then click on it
        await messagesPromise;
        await $('#home').promise();
        await this.$nextTick();
        document.getElementById("home")?.click();

        // if applicable, redirect to the user page specified in the URL
        await this.$nextTick();
        const managerButton = document.getElementById('manager');
        if (managerButton) { // if is manager
            if (new URL(window.location).searchParams.get('user')) { // and if url contains ?user=xxx
                managerButton.click(); // switch to manager dashboard
            };
        }
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

        navigate: function(event) {
            if (event.target.name == "manager") {
                this.pageTitle = event.target.text;
                this.currentView = 'manager';
            } else if (event.target.name == "admin") {
                this.currentView = 'admin';
                this.pageTitle = event.target.text;
            } else if (event.target.name == "stats") {
                this.currentView = 'stats';
                this.pageTitle = event.target.text;
            } else if (event.target.name == "home") {
                this.currentView = 'home';
                this.pageTitle = event.target.text;
            } else {
                this.pageTitle = "Préférences";
                this.currentMethod = event.target.name;
                this.currentView = 'preferences';
            }

            document.title = "ESUP OTP Manager - " + this.messages.api.menu[this.currentView];
            if(this.currentView == 'preferences') {
                document.title += " - " + this.messages.api.methods[this.currentMethod].name;
            }

            $('a').parent().removeClass('active');
            $('a').parent().attr('aria-current', 'false');
            $('#' + event.target.name).parent().addClass('active');
            $('#' + event.target.name).parent().attr('aria-current', 'page');
            if (document.getElementById("sidenav-overlay")) $('#navButton').click();
            this.getUser();
        },

        getUser: function() {
            return fetchApi({
                method: "GET",
                uri: "/api/user",
                onSuccess: res => {
                    this.setUser(res.data);
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
            });
        },

        setUser: function (data) {
            this.user.uid = this.infos.uid;
            this.user.name = this.infos.name;
            this.user.methods = data.user.methods;
            this.user.transports = data.user.transports;
        },
        getMethods: async function() {
            try {
                const methods = (await fetchApi({
                    method: "GET",
                    uri: "/api/methods",
                })).data;

                const users_methods = (await fetchApi({
                    method: "GET",
                    uri: "/manager/users_methods",
                })).data;

                this.users_methods = users_methods;
                this.setMethods(methods);
            } catch (err) {
                toast({ message: err, className: 'red darken-1' });
            }
        },
        getInfos: async function() {
            try {
                 this.infos = (await fetchApi({
                    method: "GET",
                    uri: "/manager/infos",
                })).data;
                this.$set(this.infos, "lang", localStorage.getItem("lang") || "en");
            } catch (err) {
                toast({ message: err, className: 'red darken-1' });
            }
        },
        setMethods: function (data) {
            this.methods = data.methods;
            this.cleanMethods();
        },
        getMessages: function(language) {
            language ||= localStorage.getItem("lang") || '';
            return fetchApi({
                method: "GET",
                uri: "/manager/messages/" + language,
                onSuccess: res => {
                    const { lang, messages } = res.data;
                    this.setMessages(messages);
                    $('html').attr('lang', lang);
                    localStorage.setItem("lang", lang);
                    this.infos.lang = lang;
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
            });
        },
        setMessages: function (data) {
            this.messages = data;
            this.cleanMethods();
        },
    is_authorized: function (method) {
        return !this.users_methods?.unauthorized.includes(method);
    }
  }
})
