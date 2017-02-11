const helmet = require('helmet');
const morgan = require('morgan');
const cookies = require('cookie-parser');
const bodyParser = require('body-parser');

const logger = require('../lib/logger');

module.exports = function phase(done) {
  this.use(morgan(':method :url :status :response-time ms - :res[content-length]', {
    stream: {
      write: (message) => {
        logger.debug(message.replace(/\n$/, ''));
      }
    }
  }));

  // Proxy support.
  this.enable('trust proxy');

  // Security headers.
  this.use(helmet.hsts({ maxAge: 31536000000 }));
  this.use(helmet.xssFilter());
  this.use(helmet.noSniff());
  this.use(helmet.hidePoweredBy());

  // Parsing.
  this.use(cookies());
  this.use(bodyParser.json());
  this.use(bodyParser.urlencoded({ extended: false }));

  done();
};
