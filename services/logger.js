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

if (logProperties) {
    const type = logProperties.type || 'console';

    if (type == 'console') {
        logger.add(new winston.transports.Console());
    } else if (type == 'file') {
        if ('file' in logProperties) {
            logger.add(new winston.transports.File({ filename: logProperties.file }));
        } else {
            throw new Error("logs.main.file must be defined in properties/esup.json");
        }
    } else {
        throw new Error(`invalid value '${logs.main.type}' for logs.main.type property`);
    }
}

export default logger;
