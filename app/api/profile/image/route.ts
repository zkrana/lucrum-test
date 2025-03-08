import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import prisma from '@/lib/prisma';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId');

    // Clean up userId by removing any Next.js Image parameters
    const cleanUserId = userId?.split('?')[0]?.split('&')[0];

    if (!cleanUserId || cleanUserId.trim() === '') {
      return NextResponse.json({ error: 'User ID is required' }, { status: 400 });
    }

    // Check authentication
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check if user exists and has image data
    const user = await prisma.user.findUnique({
      where: { id: cleanUserId },
      select: { image_data: true }
    });

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    if (!user.image_data) {
      return NextResponse.json({ error: 'Image not found' }, { status: 404 });
    }

    // Convert Buffer to Uint8Array if needed
    const imageData = user.image_data instanceof Buffer ? user.image_data : Buffer.from(user.image_data);

    // Determine content type based on magic numbers
    let contentType = 'image/jpeg';
    if (imageData[0] === 0x89 && imageData[1] === 0x50) {
      contentType = 'image/png';
    } else if (imageData[0] === 0x47 && imageData[1] === 0x49) {
      contentType = 'image/gif';
    }

    // Set appropriate headers for image response
    return new NextResponse(imageData, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Content-Length': imageData.length.toString(),
        'Cache-Control': 'public, max-age=31536000, immutable'
      }
    });
  } catch (error) {
    console.error('Error serving profile image:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal Server Error' },
      { status: 500 }
    );
  }
}