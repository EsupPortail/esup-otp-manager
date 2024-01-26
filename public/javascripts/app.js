/** jQuery Initialisation **/
(function ($) {
    $(function () {
        $(document).on('click', ".collapsible-header", function(){
            $(this).next('.collapsible-body').toggle(200);
        });
    }); // end of document ready
})(jQuery); // end of jQuery name space

function toggle_visibility(id) {
    var e = document.getElementById(id);
        e.style.width = "240px";
        e.style.left = "0";
}

function hide(id) {
    var e = document.getElementById(id);
    if(document.documentElement.clientWidth >= 992)
        e.style.width = "240px";
    else
        e.style.width = "0";
}

$(window).resize(function() {
    var window_width = $(window).width();
    if(window_width >= 992) {
        $("#slide-out").width(240);
        $("#closebtn").css('visibility','hidden');
    }
    else{
        $("#slide-out").width(0);
        $("#closebtn").css('visibility','visible');
    }
});

/** WebSockets init**/
var arr = window.location.href.split('/');
var urlSockets = arr[0] + "//" + arr[2];
var socket;

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
                url: this.formatApiUrl("totp/activate/confirm/" + totpCode),
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        Materialize.toast('Erreur, veuillez réessayer.', 3000, 'red darken-1');
                    } else {
                        this.user.methods.totp.active = true;
                        this.user.methods.totp.qrCode = '';
                        this.user.methods.totp.message = '';
                        Materialize.toast('Code validé', 3000, 'green darken-1');
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    console.error("/api/totp/activate/confirm", status, err.toString());
                }.bind(this)
            });
        }
    },
    template: '#totp-method'
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
            if (transport == 'sms') reg = new RegExp("^0[6-7]([-. ]?[0-9]{2}){4}$");
            else reg = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
            if (reg.test(new_transport)) {
                var oldTransport = this.user.transports[transport];
                this.user.transports[transport]= new_transport;
                document.getElementById(transport + '-input').value = '';
                $.ajax({
                    method: 'PUT',
                    url: this.formatApiUrl('transport/' + transport + '/' + new_transport),
                    dataType: 'json',
                    cache: false,
                    success: function(data) {
                        if (data.code != "Ok") {
                            this.user.transports[transport]= oldTransport;
                            document.getElementById(transport + '-input').value = oldTransport;
                            Materialize.toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                        }else Materialize.toast('Transport vérifié', 3000, 'green darken-1');
                    }.bind(this),
                    error: function(xhr, status, err) {
                        this.user.transports[transport]= oldTransport;
                        document.getElementById(transport + '-input').value = oldTransport;
                        Materialize.toast(err, 3000, 'red darken-1');
                        console.error('/api/transport/' + transport + '/' + new_transport, status, err.toString());
                    }.bind(this)
                });
            }else Materialize.toast('Format invalide.', 3000, 'red darken-1');
        },
        deleteTransport: function(transport) {
            var oldTransport = this.user.transports[transport];
            this.user.transports[transport]= null;
            $.ajax({
                method: 'DELETE',
                url: this.formatApiUrl('transport/' + transport),
                dataType: 'json',
                cache: false,
                success: function(data) {
                    if (data.code != "Ok") this.user.transports[transport]= oldTransport;
                }.bind(this),
                error: function(xhr, status, err) {
                    this.user.transports[transport]= oldTransport;
                    Materialize.toast(err, 3000, 'red darken-1');
                    console.error("/data/deactivate.json", status, err.toString());
                }.bind(this)
            });
        },
        testTransport: function(transport) {
            $.ajax({
                url: this.formatApiUrl('transport/' + transport + '/test'),
                dataType: 'json',
                cache: false,
                success: function(data) {
                    if (data.code != "Ok") Materialize.toast(data.message, 3000, 'red darken-1');
                    else Materialize.toast('Transport vérifié', 3000, 'green darken-1');
                }.bind(this),
                error: function(xhr, status, err) {
                    Materialize.toast(err, 3000, 'red darken-1');
                    console.error('/api/transport/' + transport + '/test', status, err.toString());
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
        "random_code": RandomCodeMethod,
        "random_code_mail": RandomCodeMailMethod,
	"esupnfc":Esupnfc
    },
    template: "#user-dashboard",
    created: function () {
    },
    methods: {
        formatApiUrl: function(url) {
            return '/api/' + url;
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
                case 'esupnfc':
                    this.standardActivate(method);
                    break;
                default:
                    /** **/                    
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
                    }else Materialize.toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
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
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else this.user.methods[method].active = true;
                }.bind(this),
                error: function (xhr, status, err) {
                    console.error("/api/"+method+"/activate", status, err.toString());
                }.bind(this)
            });
        },     
        deactivate: function (method) {
	  if (window.confirm(this.messages.api.action.confirm_deactivate)){
           if(this.user.methods[method].askActivation) this.user.methods[method].askActivation=false;	
            $.ajax({
                method: "PUT",
                url: "/api/" + method + "/deactivate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code != "Ok") {
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    }
                    else this.user.methods[method].active = false;
                }.bind(this),
                error: function (xhr, status, err) {
                    Materialize.toast(err, 3000, 'red darken-1');
                    console.error("/api/" + method + "/deactivate", status, err.toString());
                }.bind(this)
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
                url: "/api/generate/bypass",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") this.user.methods.bypass.codes = data.codes;
                    else if (typeof(onError) === "function") onError();
                }.bind(this),
                error: function (xhr, status, err) {
                    if (typeof(onError) === "function") onError();
                    Materialize.toast(err, 3000, 'red darken-1');
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
                    Materialize.toast(err, 3000, 'red darken-1');
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
            return '/api/admin/' + url + '/' + this.user.uid;
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
                        })
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
                    }else Materialize.toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                }.bind(this),
                error: function (xhr, status, err) {
                    Materialize.toast(err, 3000, 'red darken-1');
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
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                    }else this.user.methods[method].active = true;
                }.bind(this),
                error: function (xhr, status, err) {
                    this.user.methods[method].active = false;
                    Materialize.toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + this.user.uid + "/"+method+"/activate", status, err.toString());
                }.bind(this)
            });
        },            
        deactivate: function (method) {
         if (window.confirm(this.messages.api.action.confirm_deactivate)){
            if(this.user.methods[method].askActivation) this.user.methods[method].askActivation=false;	
            $.ajax({
                method: "PUT",
                url: "/api/admin/" + this.user.uid + "/" + method + "/deactivate",
                dataType: 'json',
                cache: false,
                success: function (data) {
                    if (data.code == "Ok") this.user.methods[method].active = false;
                    else {
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                        this.user.methods[method].active = true;
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    this.user.methods[method].active = true;
                    Materialize.toast(err, 3000, 'red darken-1');
                    console.error("/api/admin/" + this.user.uid + "/" + method + "/activate", status, err.toString());
                }.bind(this)
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
                    Materialize.toast(err, 3000, 'red darken-1');
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
                    Materialize.toast(err, 3000, 'red darken-1');
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
                for (uid in this.uids) {
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
                Materialize.toast('utilisateur '+$('#autocomplete-input').val()+' ajouté avec succès', 3000, 'green darken-1');
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
                    Materialize.toast(err, 3000, 'red darken-1');
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
                    Materialize.toast(err, 3000, 'red darken-1');
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
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else {
                        this.methods[event.target.name].activate = true;
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = false;
                    Materialize.toast(err, 3000, 'red darken-1');
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
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else this.methods[event.target.name].activate = false;
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = true;
                    Materialize.toast(err, 3000, 'red darken-1');
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
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard.', 3000, 'red darken-1');
                    } else {
                        this.methods[method].transports.push(transport);
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = false;
                    Materialize.toast(err, 3000, 'red darken-1');
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
                        Materialize.toast('Erreur interne, veuillez réessayer plus tard', 3000, 'red darken-1');
                    } else {
                        var index = this.methods[method].transports.indexOf(transport);
                        if (index > (-1)) this.methods[method].transports.splice(index, 1);
                    }
                }.bind(this),
                error: function (xhr, status, err) {
                    event.target.checked = true;
                    Materialize.toast(err, 3000, 'red darken-1');
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
            for (method in this.methods) {
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
                    Materialize.toast(err, 3000, 'red darken-1');
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
                            Materialize.toast(err, 3000, 'red darken-1');
                            console.error("/manager/users_methods", status, err.toString());
                        }.bind(this)
                    });
                }.bind(this),
                error: function (xhr, status, err) {
                    Materialize.toast(err, 3000, 'red darken-1');
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
                url: "/api/messages"+query,
                dataType: 'json',
                cache: false,
                success: function (data) {
                    this.setMessages(data);
                }.bind(this),
                error: function (xhr, status, err) {
                    Materialize.toast(err, 3000, 'red darken-1');
                    console.error("/api/messages", status, err.toString());
                }.bind(this)
            });
        },
        setMessages: function (data) {
            this.messages = data;
            this.cleanMethods();
        },
	checkAcl: function(method,acl){
	 var result=false;
	 var not="";	
	 if(acl=="deny"){
		result=true;
		not="not ";		
	  }
	  if(this.users_methods[method][acl] && this.users_methods.user.attributes)
	    for(attr in this.users_methods[method][acl]) {
              //console.debug("this.users_methods["+method+"]["+acl+"]: "+JSON.stringify(this.users_methods[method][acl]));
	      //console.debug("User: "+JSON.stringify(this.users_methods.user));   
	      if(this.users_methods.user.attributes[attr])
		for(valueAttr of this.users_methods[method][acl][attr])
  		    if(this.users_methods.user.attributes[attr].includes(valueAttr)){
                	//console.debug("{"+method+"} method is "+not+"displayed because user attribute {"+attr+"} contains {"+valueAttr+"}"); 		
			return !result;
		    }	        	      
             }         	    
	  return result;  
	},
	is_authorized: function(method){
	 var result=true; //par défaut, la méthode est autorisée
	 if(this.users_methods && this.users_methods[method])
	    for(acl in this.users_methods[method])//pour une méthode, la priorité porte sur le dernier acl [allow|deny].
		result=this.checkAcl(method,acl); 
	    
	 return result;
	} 
  }
})
