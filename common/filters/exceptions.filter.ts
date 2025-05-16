
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

//Filter to handle and log all exceptions globally
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {

    private readonly logger = new Logger(AllExceptionsFilter.name);
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;

    console.log(exception);
    const message =exception instanceof HttpException ? exception.getResponse(): 'Internal server error';

    const formattedMessage =typeof message === 'string'? { message }: typeof message === 'object'? message: { message: 'Something went wrong' };

        this.logger.error(
      `HTTP ${status} Error on ${request.method} ${request.url}`,
      JSON.stringify({
        timestamp: new Date().toISOString(),
        path: request.url,
        method: request.method,
        statusCode: status,
        ...formattedMessage,
      }),
    );
    response.status(status).json({
      timestamp: new Date().toISOString(),
      path: request.url,
      statusCode: status,
      ...formattedMessage,
    });
  }
}
