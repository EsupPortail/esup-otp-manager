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
    $('.toast').last().attr('role', 'alert');
}

/** Vue.JS **/

/** User **/
const PushMethod = {
    props: {
        'user': Object,
        'getAndSetUser': Function,
        'messages': Object,
        'infos': Object,
        'activate': Function,
        'deactivate': Function,
    },
    data() {
        return {
            'socket': Object,
        };
    },
    watch: {
        'user.uid': {
            handler(uid, old, onCleanup) {
                this.cleanupSocket();

                this.socket = io.connect({ reconnect: true, path: "/sockets", query: 'uid=' + uid });
                this.socket.on('userPushActivate', () => {
                    this.getAndSetUser(uid);
                });

                this.socket.on('userPushDeactivate', () => {
                    this.getAndSetUser(uid);
                });

                onCleanup(() => {
                    this.cleanupSocket();
                })
            },
            immediate: true,
        },
    },
    methods: {
        cleanupSocket: function() {
            this.socket?.disconnect?.();
            delete this.socket;
        }
    },
    template: '#push-method'
};

const BypassMethod = {
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
};

const dateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
};

const PasscodeGridMethod = {
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
};

const TotpMethod = {
    props: {
        'user': Object,
        'generate_totp': Function,
        'activate': Function,
        'deactivate': Function,
        'messages': Object,
        'infos': Object,
        'formatApiUri': Function,
    },
    computed: {
        EsupAuth() {
            if (!this.infos.mobile) {
                return this.infos.esup_auth_download_link;
            }
            return `<a href="${this.infos.EsupAuth[this.infos.mobile]}" target="_blank">Esup Auth</a>`;
        },
        authentificators() {
            const authenticatorApps = [
                { name: "Google Authenticator", android: "https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2", ios: "https://apps.apple.com/fr/app/google-authenticator/id388497605" },
                { name: "Microsoft Authenticator", android: "https://play.google.com/store/apps/details?id=com.azure.authenticator", ios: "https://apps.apple.com/fr/app/microsoft-authenticator/id983156458" },
                { name: this.messages.api.methods.totp.apple_passwords_app, ios: "apple-otpauth://totp/" },
                { name: "FreeOTP", android: "https://play.google.com/store/apps/details?id=org.fedorahosted.freeotp", ios: "https://apps.apple.com/us/app/freeotp-authenticator/id872559395" },
                { name: "Aegis Authenticator", android: "https://play.google.com/store/apps/details?id=com.beemdevelopment.aegis" },
            ];
            if(!this.infos.mobile) {
                return `${this.infos.esup_auth_download_link}, ${authenticatorApps.map(app => app.name).join(", ")}, ...`;
            }
            authenticatorApps.unshift(this.infos.EsupAuth);
            return authenticatorApps
                .map(app => ({ name: app.name, url: app[this.infos.mobile] }))
                .filter(app => app.url)
                .map(app => `<a href="${app.url}" target="_blank">${app.name}</a>`)
                .join(", ")
                .concat(", ...");
        }
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
                        this.user.methods.totp.askActivation = false;
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
};

const WebAuthnMethod = {
    props: {
        'user': Object,
        'activate': Function,
        'deactivate': Function,
        'messages': Object,
        'infos': Object,
        'formatApiUri': Function,
        'fetchWebauthnData': Function,
    },
    data() {
        return {
            webauthnData: { // example (will be override by mounted() )
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
        await this.updateWebauthnData();

        if(this.webauthnData.auths.length === 0) {
            this.generateWebauthn();
        }
    },
    computed: {
        descriptionMessage() {
            switch (this.webauthnData.auths.length) {
                case 0:
                    return this.messages.api.methods.webauthn.no_authentificators;
                case 1:
                    return this.messages.api.methods.webauthn.single_auth;
                default:
                    return this.messages.api.methods.webauthn.nb_of_auths.replace('%NB%', this.webauthnData.auths.length);
            }
        },
    },
    watch: {
        'user.uid': function(newUid, oldUid) {
            if (newUid !== oldUid) {
                this.updateWebauthnData();
            }
        },
        'webauthnData.auths.length': {
            handler(lenght) {
                this.user.methods.webauthn.askActivation = !lenght
            },
            immediate: true,
        },
    },
    methods: {
        updateWebauthnData: async function() {
            this.webauthnData = await this.fetchWebauthnData();
            return this.webauthnData;
        },
        getAuthById: function (id) {
            return this.webauthnData.auths.find(authenticator => authenticator.credentialID === id);
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
                        await this.updateWebauthnData();
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
                        await this.updateWebauthnData();
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
                const data = await this.updateWebauthnData();

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
                            await this.updateWebauthnData();
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
};

const TransportForm = {
    props: {
        'user': Object,
        'messages': Object,
        'infos': Object,
        'transport': String,
        'inputType': String,
        'testAndSaveTransport': Function,
        'saveTransport': Function,
        'deleteTransport': Function,
        'isManager': Boolean,
    },
    template: '#transport_form'
};

const RandomCodeMethod = {
    props: {
        'user': Object,
        'messages': Object,
        'infos': Object,
        'activate': Function,
        'deactivate': Function,
        'hasValidTransportForRandom_codeMethod': Function,
        'formatApiUri': Function,
        'isManager': Boolean,
        'method': String,
    },
    components: {
        'transport-form': TransportForm,
    },
    watch: {
        "user.transports": {
            handler() {
                this.user.methods[this.method].askActivation = !this.hasValidTransportForRandom_codeMethod(this.method);
            },
            deep: true,
            immediate: true,
        },
    },
    methods: {
        testAndSaveTransport: async function(transport) {
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
                        preConfirm: () => this.saveTransport(transport),
                    });
                }
            } catch (err) {
                toast({ message: err, className: 'red darken-1' });
            };
        },
        saveTransport: async function(transport) {
            const new_transport = document.getElementById(transport + '-input').value.trim();
            const res = await fetchApi({
                method: "PUT",
                uri: this.formatApiUri('/transport/' + transport + '/' + new_transport),
            });
            const data = res.data;
            if (data.code != "Ok") {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            } else {
                this.user.transports[transport] = new_transport;
                document.getElementById(transport + '-input').value = '';
                toast({ message: this.messages.success.update, className: 'green contrasted' });
            }
        },
        deleteTransport: function(transport) {
            const oldTransport = this.user.transports[transport];
            const message = this.messages.api.methods.random_code?.confirm_delete?.[transport]?.replace("%TRANSPORT%", oldTransport);
            if (window.confirm(message)) {
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
            }
        },
    },
    template: '#random_code-method'
};

const RandomCodeMailMethod = { 
    ...RandomCodeMethod,
    template: '#random_code_mail-method'
};

const Esupnfc = {
    template:'#esupnfc-method'
};

const UserDashboard = {
    props: {
        'user': Object,
        'methods': Object,
        'messages': Object,
        'infos': Object,
        'getAndSetUser': Function,
        'currentmethod': String,
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
    watch: {
        currentmethod: {
            async handler(currentmethod) {
                if (!currentmethod) {
                    return;
                }
                if (this.user.methods[currentmethod].active) {
                    return;
                }

                if (currentmethod === "webauthn") {
                    const webauthnData = await this.fetchWebauthnData();
                    if (webauthnData.auths.length) {
                        return;
                    }
                }

                switch (currentmethod) {
                    case "random_code":
                    case "random_code_mail":
                        if (this.hasValidTransportForRandom_codeMethod(currentmethod)) {
                            return
                        }
                    case "webauthn":
                    case "push":
                    case "totp":
                        return this.activate(currentmethod);
                }
            },
            immediate: true,
        }
    },
    methods: {
        formatApiUri: function(uri) {
            return '/api' + uri;
        },
        activate: async function(method) {
            switch (method) {
                case 'push':
                    return this.askPushActivation();
                case 'bypass':
                    await this.standardActivate(method);
                    return this.generateBypass();
                case 'passcode_grid':
                    const { data } = await this.standardActivate(method);
                    return this.setPasscodeGrid(data);
                case 'totp':
                    return this.generateTotp();
                default:
                    return this.standardActivate(method);
            }
        },
        askPushActivation: function() {
            return fetchApi({
                method: "PUT",
                uri: this.formatApiUri("/push/activate"),
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.push.active = true;
                        this.user.methods.push.askActivation = true;
                        this.user.methods.push.activationCode = data.activationCode;
                        this.user.methods.push.qrCode = getImgWithAltText({ qrCodeImg: data.qrCode, qrCodeSrc: data.qrCodeSrc });
                        this.user.methods.push.deepLink = data.deepLink;
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
                uri: this.formatApiUri("/" + method + "/activate"),
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
                throw err;
            });
        },
        deactivate: function(method) {
            if (window.confirm(this.messages.api.action.confirm_deactivate)) {
                return fetchApi({
                    method: "PUT",
                    uri: this.formatApiUri("/" + method + "/deactivate"),
                    onSuccess: res => {
                        const data = res.data;
                        if (data.code == "Ok") {
                            this.user.methods[method].askActivation = false;
                            this.user.methods[method].active = false;
                        } else {
                            console.error(JSON.stringify({ code: data.code }));
                            throw new Error("Erreur interne, veuillez réessayer plus tard.");
                        }
                    },
                }).catch(err => {
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
                uri: this.formatApiUri("/generate/bypass"),
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
                this.user.methods.bypass.active = false;
                throw err;
            });
        },
        generatePasscodeGrid: function() {
            return fetchApi({
                method: "POST",
                uri: this.formatApiUri("/generate/passcode_grid"),
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
            this.user.methods.passcode_grid.grid = data.grid;
            this.user.methods.passcode_grid.generation_date = data.generation_date;
        },
        generateTotp: function() {
            return fetchApi({
                method: "POST",
                uri: this.formatApiUri("/generate/totp?require_method_validation=true"),
                onSuccess: res => {
                    const data = res.data;
                    if (data.code == "Ok") {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.askActivation = true;
                        this.user.methods.totp.secret = data.message;
                        this.user.methods.totp.qrCode = getImgWithAltText({ qrCodeImg: data.qrCode, qrCodeSrc: data.qrCodeSrc });
                        this.user.methods.totp.deepLink = data.deepLink;
                        this.user.methods.totp.uri = data.uri;
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
        hasValidTransportForRandom_codeMethod: function(method) {
            return this.user
                .methods[method].transports
                .some(transport => this.user.transports[transport]);
        },
        fetchWebauthnData: async function() {
            const { data } = await fetchApi({
                method: "POST",
                uri: this.formatApiUri("/generate/webauthn"),
            });
            return data;
        },
    },
};

/** Manager **/
const UserView = {
    ...UserDashboard,
    template: '#user-view',
    methods: {
        ...UserDashboard.methods,
        formatApiUri: function(uri) {
            return '/api/admin/' + this.user.uid + uri;
        },
    },
};

const ManagerDashboard = {
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
                displayName: String,
                methods: Object,
                transports: Object
            },
            users: [],
            requestedUid: '',
            debounceTimeout: null,
        }
    },
    watch: {
        requestedUid: function(newVal) {
            clearTimeout(this.debounceTimeout);

            this.debounceTimeout = setTimeout(() => {
                this.fetchUsersByToken(newVal);
            }, 300);
        }
    },
    mounted: async function() {
        const url = new URL(location);
        const user = url.searchParams.get('user');
        if (user) { // if url contains ?user=xxx
            await this.$nextTick();
            await this.getAndSetUser(user); // display user xxx
            await this.$nextTick();
            url.searchParams.set('user', '');
            history.pushState({}, '', url); // and remove xxx from current url
        }
    },
    methods: {
        fetchUsersByToken: function(token) {
            if (token?.length < 3) {
                this.users = [];
                return;
            }

            fetchApi({
                method: "GET",
                uri: `/api/admin/users?token=${encodeURIComponent(token)}`,
                onSuccess: res => {
                    this.users = res.data.users;
                }
            }).catch(err => {
                toast(err, 3000, 'red darken-1');
            });
        },
        checkUserThenGetAndSet: async function() {
            if (this.requestedUid) {
                if (await this.user_exists(this.requestedUid) || window.confirm("Aucun utilisateur avec pour identifiant '" + this.requestedUid + "' n'existe en base de données. Souhaitez-vous le créer ?")) {
                    this.getAndSetUser(this.requestedUid);
                    this.requestedUid = '';
                }
            }
        },
        user_exists: async function(uid) {
            if (this.users.some(user => user.uid == uid)) {
                return true;
            }
            return (await fetchApi({
                method: "GET",
                uri: `/api/admin/user/${uid}/exists`,
            })).data.user_exists;
        },
        getAndSetUser: function(uid) {
            return fetchApi({
                method: "GET",
                uri: "/api/admin/user/" + uid,
                onSuccess: res => {
                    this.setUser(uid, res.data.user);
                },
            }).catch(err => {
                toast({ message: err, className: 'red darken-1' });
            });
        },
        setUser: function(uid, user) {
            this.user = {
                uid: uid,
                displayName: user.displayName,
                methods: user.methods,
                transports: user.transports,
            }
        }
    },
    template: '#manager-dashboard'
};

/** Admin **/
const AdminDashboard = {
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
};

/** Stats  **/
const StatsDashboard = {
    props: {
        messages: Object,
    },
    data() {
        return {
            data: {},
            loading: false,
            chart: null,
            chart2: null,
        };
    },
    methods: {
        fetchStats() {
            this.loading = true;
            fetchApi({
                method: 'GET',
                uri: '/api/admin/stats',
                onSuccess: async res => {
                    this.data = res.data;
                    this.loading = false;
                    await this.$nextTick();
                    await this.renderChart(); // appel une fois le DOM mis à jour
                },
            }).catch(err => {
                toast({ message: 'Erreur interne, veuillez réessayer plus tard.', className: 'red darken-1' });
            });
        },
        async renderChart() {


            await import ("/js/chart.js");
            await import ("/js/chartjs-plugin-datalabels.min.js");

            // this.data example :
            // {"totalUsers":32507,"totalMfaUsers":1887,"methods":{"totp":588,"bypass":838,"passcode_grid":38,"push":1072,"esupnfc":195,"webauthn":518},"pushPlatforms":{"iOS":354,"Android":716,"Mac":2}}

            const totalUsers = this.data.totalUsers;
            const totalMfaUsers = this.data.totalMfaUsers;

            if (this.chart) {
                this.chart.destroy(); // évite les superpositions
            }
            if (this.chart2) {
                this.chart2.destroy();
            }

            const statsChartMfaMethods = document.getElementById('statsChartMfaMethods');
            if(typeof statsChartMfaMethods !== 'undefined' && statsChartMfaMethods !== null) {

                const ctx = statsChartMfaMethods.getContext('2d');

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
                        interaction: {
                            // show all data for this label on hover
                            mode: 'index'
                        },
                        plugins: {
                            title: {
                                display: true,
                                text: title,
                            },
                            tooltip: {
                                callbacks: {
                                    label: function (context) {
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

            const statsChartPushPlatforms = document.getElementById('statsChartPushPlatforms');
            if(typeof statsChartPushPlatforms !== 'undefined' && statsChartPushPlatforms !== null) {

                const pushPlatforms = this.data.pushPlatforms;
                const pushPlatformsLabels = Object.keys(pushPlatforms);
                const pushPlatformsData = Object.values(pushPlatforms);
                const totalMfaPushUsers = pushPlatformsData.reduce((a, b) => a + b, 0);

                // statsChartPushPlatforms as a pie chart
                const title = this.messages.stats.chart_platforms_title
                    .replace("%NB_USERS_MFA_PUSH%", totalMfaPushUsers)
                    .replace("%NB_USERS_MFA%", totalMfaUsers);

                const ctx2 = statsChartPushPlatforms.getContext('2d');
                this.chart2 = new Chart(ctx2, {
                    type: 'pie',
                    data: {
                        labels: pushPlatformsLabels,
                        datasets: [{
                            data: pushPlatformsData
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: title,
                            },
                            legend: {
                                onHover: (evt, legendItem) => {
                                    const activeElement = {
                                        datasetIndex: 0,
                                        index: legendItem.index
                                    };
                                    this.chart2.tooltip.setActiveElements([activeElement]);
                                    this.chart2.update();
                                }
                            }
                        }
                    },
                    plugins: [ChartDataLabels]
                });
            }

            const methodsCount = this.data.users?.methodsCount
            const statsChartMfaMethodsCount = document.getElementById('statsChartMfaMethodsCount');
            if (statsChartMfaMethodsCount && methodsCount) {
                this.chartMethodsCount?.destroy();

                const methodsCountArray = Object.entries(methodsCount)

                const ctx = statsChartMfaMethodsCount.getContext('2d');
                this.chartMethodsCount = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: methodsCountArray.map(([count, _nb_users]) => this.messages.stats.methodsCount.label.replace("%NB_METHODS%", count)),
                        datasets: [{
                            data: methodsCountArray.map(([_count, nb_users]) => nb_users),
                            backgroundColor: '#66BB6A',
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: this.messages.stats.methodsCount.title,
                            },
                            legend: {
                                display: false,
                            },
                            tooltip: {
                                callbacks: {
                                    label: context => this.messages.stats.methodsCount.context.replace("%NB_USERS%", context.raw),
                                }
                            },
                            datalabels: {
                                anchor: 'end',
                                align: 'top',
                                font: {
                                    weight: 'bold',
                                }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0,
                                }
                            }
                        }
                    },
                    plugins: [ChartDataLabels],
                });
            }

        }
    },
    mounted() {
        this.fetchStats();
    },
    template: '#stats-dashboard',
};


/** Admin **/
const Home = {
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
};

/** Main **/
Vue.createApp({
    components: {
        "home": Home,
        "preferences": UserDashboard,
        "manager": ManagerDashboard,
        "admin": AdminDashboard,
        "stats": StatsDashboard
    },
    data() {
      return {
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
        messages: {},
        infos: {
            api_url: "",
            uid: "",
            name: "",
            transport_regexes: {
                sms: "",
                mail: "",
            },
            lang: localStorage.getItem("lang") || "en",
            isMacOs: navigator.platform.startsWith("Mac"),
            mobile: /Android/i.test(navigator.userAgent) ? "android" :
                    /iPhone|iPad|iPod/i.test(navigator.userAgent) ? "ios" :
                    false,
            EsupAuth: { name: "Esup Auth", android: "https://play.google.com/store/apps/details?id=org.esupportail.esupAuth", ios: "https://apps.apple.com/fr/app/esup-auth/id1563904941" },
        },
        has_window_opener: Boolean(window.opener),
      };
    },
    watch: {
        messages: {
            handler(messages) {
                if (!this.infos.mobile) {
                    this.infos.esup_auth_download_link = messages?.api?.methods.push.esup_auth_download_link
                        .replace("%ANDROID_URL%", this.infos.EsupAuth.android)
                        .replace("%IOS_URL%", this.infos.EsupAuth.ios);
                } else {
                    this.infos.esup_auth_download_link = `<a href="${this.infos.EsupAuth[this.infos.mobile]}" target="_blank">Esup Auth</a>`;
                }
            },
            immediate: true,
        },
        has_active_method(val, prev) {
            // on small screens, show the menu which contains closeOtpManager button
            if (val && prev === false) toggle_visibility('slide-out')
        },
    },
    computed: {
        has_active_method() {
            const methods = Object.entries(this.user.methods)
            if (methods.length === 0) return undefined
            return methods
                .filter(([_key, value]) => value.active && !value.askActivation)
                .length > 0
        }
    },
    created: async function() {
        const messagesPromise = this.getMessages();
        this.getMethods();
        await this.getInfos();
        this.getAndSetUser();

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
            this.getAndSetUser();
        },

        getAndSetUser: function() {
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
                const infos = await fetchApi({
                    method: "GET",
                    uri: "/manager/infos",
                });
                Object.assign(this.infos, infos.data);
            } catch (err) {
                toast({ message: err, className: 'red darken-1' });
            }
        },
        setMethods: function (data) {
            this.methods = data.methods;
            this.cleanMethods();
        },
        closeOtpManagerWindow() {
            window.opener.postMessage('closeOtpManagerWindow', '*')
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
}).mount('#app')
