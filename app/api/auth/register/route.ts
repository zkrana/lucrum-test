import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const { 
      name, email, password, 
      authProvider, providerAccountId, access_token, refresh_token, expires_at, id_token 
    } = await request.json();

    // Determine Signup Type
    const isSocialAuth = authProvider === 'GOOGLE' || authProvider === 'APPLE';
    const isManualAuth = !isSocialAuth;

    let endpoint = 'http://localhost:8000/api/rest-api/auth/manual_register.php';
    // Validate email
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return NextResponse.json({ error: 'Valid email is required' }, { status: 400 });
    }
    let bodyData: any = { 
      name: name || email.split('@')[0], // Default name if missing 
      email 
    };

    if (isManualAuth) {
      // Manual signup requires password
      if (!password) {
        return NextResponse.json({ error: 'Password is required for manual signup' }, { status: 400 });
      }
      bodyData.password = password;
    } else {
      // Social signup (Google/Apple)
      endpoint = 'http://localhost:8000/api/rest-api/auth/provider_register.php';
      if (!providerAccountId || !access_token) {
        return NextResponse.json({ error: 'Provider account details are required' }, { status: 400 });
      }
      bodyData = {
        email,
        name: name || email.split('@')[0],
        googleId: providerAccountId, // Map providerAccountId to googleId
        access_token,
        refresh_token,
        expires_at,
        id_token
      };
    }

    // Send request to the correct PHP endpoint
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
    console.error('Registration error:', {
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    });

    // Handle network errors
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return NextResponse.json({ error: 'Unable to connect to authentication server' }, { status: 503 });
    }

    return NextResponse.json({ 
      error: 'Internal Server Error',
      message: 'An unexpected error occurred during registration'
    }, { status: 500 });
  }
}