const winston = require('winston');
const path = require('node:path');
const properties = require(__dirname + '/../properties/properties');

const logger = winston.createLogger({
    level: properties.esup.logs.error.level || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(options => {
            return `${options.timestamp} ${options.level.toUpperCase()} ${undefined !== options.message ? options.message : ''}` +
                (options.meta && Object.keys(options.meta).length ? `\n\t${JSON.stringify(options.meta)}` : '');
        })
    ),
});

if (properties.esup.logs.error.file) {
   logger.add(new winston.transports.File({ filename: properties.esup.logs.error.file }));
} else {
    logger.add(new winston.transports.Console());
}

module.exports = logger;
