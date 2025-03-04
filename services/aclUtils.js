import properties from "../properties/properties.js";
const { esup } = properties;
import logger from "./logger.js";

normalizeEsupProperties();

/**
 * exported for testing purposes only
 */
export function normalizeEsupProperties() {
    for (const esupAttributesName of ["admins_attributes", "managers_attributes"]) {
        convertValuesToArrayOfLowerCasedString(esup[esupAttributesName]);
    }

    const users_methods = esup.users_methods;

    for (const methodName in esup.users_methods) {
        if (methodName.startsWith("#")) {
            delete users_methods[methodName];
        } else {
            const { allow, deny } = users_methods[methodName];
            // prevent from defining allow AND deny for one method
            if (allow && deny) {
                throw new Error("Only one filter between 'deny' and 'allow' can be defined by users_method (problematic users_method: " + methodName + ")");
            } else if (!(allow || deny)) {
                logger.warn(methodName + " method has no 'allow' or 'deny' filter defined");
                delete users_methods[methodName];
            } else {
                // lowercase all attribute values
                for (const acl in { allow, deny }) {
                    if (users_methods[methodName][acl]) {
                        users_methods[methodName] = { [acl]: users_methods[methodName][acl] };

                        convertValuesToArrayOfLowerCasedString(users_methods[methodName][acl]);
                    }
                }
            }
        }
    }
}

/**
 * @param {Object.<String, String|Array.<String>>} attributes
 */
function convertValuesToArrayOfLowerCasedString(attributes) {
    for (const attr in attributes) {
        let values = attributes[attr];
        if (!Array.isArray(values)) {
            values = attributes[attr] = [values];
        }

        // lowercase all attribute values
        for (const index in values) {
            values[index] = values[index]?.toLowerCase();
        }
    }
}

/**
 * lowerCase all attribute values
 */
export function prepareUserForAcl(user) {
    convertValuesToArrayOfLowerCasedString(user.attributes);
}

export function is_admin(user) {
    return is(user, 'admins');
}

export function is_manager(user) {
    return is(user, 'managers');
}

/**
 * @param {('managers'|'admins')} status
 */
function is(user, status) {
    return esup[status].includes(user.uid) ||
        matchAttributes(user.attributes, esup[status + "_attributes"]);
}

export function getUnauthorizedMethods(user) {
    const unauthorized = [];
    for (const methodName in esup.users_methods) {
        if (!is_authorized(user, methodName)) {
            unauthorized.push(methodName);
        }
    }
    return unauthorized;
}

export function is_authorized(user, methodName) {
    const users_method = esup.users_methods?.[methodName];

    if (!users_method) {
        return true;
    }

    for (const acl in users_method) {
        const match = matchAttributes(user.attributes, users_method[acl]);
        switch (acl) {
            case 'allow':
                return match;
            case 'deny':
                return !match;
        }
    }
}

/**
 * @param {Object.<String, Array.<string>>} userAttributes
 * @param {Object.<String, Array.<string>>} requiredAttributes
 */
function matchAttributes(userAttributes, requiredAttributes) {
    for (const name in requiredAttributes) {
        if (userAttributes[name]) {
            if (matchAttribute(userAttributes[name], requiredAttributes[name])) {
                return true;
            }
        }
    }
    return false;
}

/**
 * @param {Array.<string>} userAttributeValues
 * @param {Array.<string>} requiredAttributeValues
 */
function matchAttribute(userAttributeValues, requiredAttributeValues) {
    for (const requiredAttributeValue of requiredAttributeValues) {
        if (userAttributeValues.includes(requiredAttributeValue)) {
            return true;
        }
    }
    return false;
}
