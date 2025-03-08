import { NextResponse } from 'next/server';

interface SocialAuthData {
  email: string;
  name: string;
  googleId: string;
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  id_token?: string;
}

interface ManualAuthData {
  name: string;
  email: string;
  password: string;
}

export async function POST(request: Request) {
  try {
    const { 
      name, email, password, 
      authProvider, providerAccountId, access_token, refresh_token, expires_at, id_token 
    } = await request.json();

    const isSocialAuth = authProvider === 'GOOGLE' || authProvider === 'APPLE';
    const isManualAuth = !isSocialAuth;

    let endpoint = 'http://localhost:8000/api/rest-api/auth/manual_register.php';
    
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return NextResponse.json({ error: 'Valid email is required' }, { status: 400 });
    }

    let bodyData: ManualAuthData | SocialAuthData;

    if (isManualAuth) {
      if (!password) {
        return NextResponse.json({ error: 'Password is required for manual signup' }, { status: 400 });
      }
      bodyData = {
        name: name || email.split('@')[0],
        email,
        password
      };
    } else {
      endpoint = 'http://localhost:8000/api/rest-api/auth/provider_register.php';
      if (!providerAccountId || !access_token) {
        return NextResponse.json({ error: 'Provider account details are required' }, { status: 400 });
      }
      bodyData = {
        email,
        name: name || email.split('@')[0],
        googleId: providerAccountId,
        access_token,
        refresh_token,
        expires_at,
        id_token
      };
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(bodyData)
    });

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json({ error: data.message || 'Registration failed' }, { status: response.status });
    }

    return NextResponse.json({ 
      success: true, 
      message: 'Registration successful',
      user: data.user
    });

  } catch (error) {
    console.error('Registration error:', error);

    if (error instanceof TypeError && error.message.includes('fetch')) {
      return NextResponse.json({ error: 'Unable to connect to authentication server' }, { status: 503 });
    }

    return NextResponse.json({ 
      error: 'Internal Server Error',
      message: 'An unexpected error occurred during registration'
    }, { status: 500 });
  }
}