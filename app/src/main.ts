import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import rateLimit from 'express-rate-limit';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // The framework name provides no learning value and needlessly helps remote
  // fingerprinting if a user later places the lab behind an approved proxy.
  app.getHttpAdapter().getInstance().disable('x-powered-by');

  // Rate limiting for DoS protection (S4)
  // Intentionally set high for learning purposes
  app.use(
    rateLimit({
      windowMs: 60 * 1000, // 1 minute
      max: 100, // 100 requests per minute
      message: { error: 'Too many requests', statusCode: 429 },
      standardHeaders: true,
      legacyHeaders: false,
    }),
  );

  await app.listen(3000);
  console.log('SOC-Lab App is running on port 3000');
}
bootstrap();

