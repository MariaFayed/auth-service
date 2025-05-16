import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { AllExceptionsFilter } from 'common/filters/exceptions.filter';
import { LoggerService, ValidationPipe  } from '@nestjs/common';
import { winstonLogger as logger } from './logger/winston-cloudwatch-logger';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  
    const app = await NestFactory.create(AppModule, {
    bufferLogs: true, 
      logger: {
      log: (message: string) => logger.info(message),
      error: (message: string, trace: string) => logger.error(message + '\n' + trace),
      warn: (message: string) => logger.warn(message),
      debug: (message: string) => logger.debug(message),
      verbose: (message: string) => logger.verbose(message),
    } as LoggerService,
  });

  const configService = app.get(ConfigService);
  
  app.useGlobalPipes(new ValidationPipe());
  app.use(cookieParser());
  app.enableCors({
    origin: configService.get<string>('FRONTEND_URI'),
    credentials: true,
  });
  app.useGlobalFilters(new AllExceptionsFilter());

      const config = new DocumentBuilder()
    .setTitle('My API')
    .setDescription('The API documentation')
    .setVersion('1.0')
    .addBearerAuth() 
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document); // Swagger will be available at /api/docs
  
  await app.listen(process.env.PORT || 4000);
}
bootstrap();
