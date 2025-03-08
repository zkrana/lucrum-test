import { SignJWT } from 'jose';

export async function generateJWTToken(userId: string): Promise<string> {
  if (!process.env.JWT_SECRET_KEY) {
    throw new Error('JWT_SECRET_KEY is not defined');
  }

  if (!userId) {
    throw new Error('User ID is required for JWT token generation');
  }

  const secret = new TextEncoder().encode(process.env.JWT_SECRET_KEY);
  const alg = 'HS256';

  const jwt = await new SignJWT({ 
    sub: userId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
  })
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);

  return jwt;
}