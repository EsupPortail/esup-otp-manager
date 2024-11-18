var properties = require(__dirname+'/../properties/properties');

exports.is_admin = function(user){
    var result = false;
    if(properties.esup.admins.includes(user.uid)) {
	result=true;
    }
    if(!result && properties.esup.admins_attributes && user.attributes) {
	for(attr in properties.esup.admins_attributes) {
	    if(user.attributes[attr] && user.attributes[attr].includes(properties.esup.admins_attributes[attr])) {
		result=true;
		break;
	    }
	}
    }
    return result;
}

exports.is_manager = function(user){
    var result = false;
    if(properties.esup.managers.includes(user.uid)) {
	result=true;
    }
    if(!result && properties.esup.managers_attributes && user.attributes) {
	for(attr in properties.esup.managers_attributes) {
	    if(user.attributes[attr] && user.attributes[attr].includes(properties.esup.managers_attributes[attr])) {
		result=true;
		break;
	    }
	}
    }
    return result;
}

exports.isAuthenticated = function(req) {
    return Boolean(req.session.passport?.user);
}

const supportedLanguages = Object.keys(properties)
    .filter(key => key.startsWith('messages_'))
    .map(key => key.replace('messages_', ''));

exports.getMessagesForRequest = function(req) {
    let lang = req.acceptsLanguages(supportedLanguages) || properties.esup.default_language || "en";
    if (req.params.language && supportedLanguages.includes(req.params.language)) {
        lang = req.params.language;
    }

    return {
        messages: properties["messages_" + lang],
        lang: lang,
    };
}
