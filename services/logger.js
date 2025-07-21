import * as winston from 'winston';
import properties from "../properties/properties.js";

const logProperties = properties.esup.logs?.main;

/**
 * @type { winston.Logger }
 */
const logger = winston.createLogger({
    level: logProperties.level || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(options => {
            return `${options.timestamp} ${options.level.toUpperCase()} ${undefined !== options.message ? options.message : ''}` +
                (options.meta && Object.keys(options.meta).length ? `\n\t${JSON.stringify(options.meta)}` : '');
        })
    ),
    handleRejections: true,
    handleExceptions: true,
});

if (logProperties.console) {
    logger.add(new winston.transports.Console());
}

if (logProperties.file) {
    logger.add(new winston.transports.File({ filename: logProperties.file }));
}

export default logger;
