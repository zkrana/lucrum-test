import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import prisma from '@/lib/prisma';

export async function POST(request: Request) {
  try {
    // Check authentication
    const session = await getServerSession(authOptions);
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Get and validate the form data
    if (!request || !request.body) {
      return NextResponse.json({ 
        error: 'Invalid request',
        message: 'Request body is missing'
      }, { status: 400 });
    }

    let formData;
    try {
      formData = await request.formData();
    } catch (formError) {
      console.error('Error parsing form data:', formError);
      return NextResponse.json({ 
        error: 'Invalid form data',
        message: formError instanceof Error ? formError.message : 'Error parsing form data'
      }, { status: 400 });
    }

    const file = formData.get('file');
    if (!file || !(file instanceof Blob)) {
      return NextResponse.json({ error: 'No valid file uploaded' }, { status: 400 });
    }

    // Validate file type
    const validMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!validMimeTypes.includes(file.type)) {
      return NextResponse.json({
        error: 'Invalid file type',
        message: 'Only JPEG, PNG, and GIF images are allowed'
      }, { status: 400 });
    }

    // Validate file size (5MB limit)
    const maxSize = 5 * 1024 * 1024;
    if (file.size > maxSize) {
      return NextResponse.json({
        error: 'File too large',
        message: 'Maximum file size is 5MB'
      }, { status: 400 });
    }

    // Convert file to buffer with proper error handling
    let buffer: Buffer;
    try {
      const arrayBuffer = await file.arrayBuffer();
      buffer = Buffer.from(arrayBuffer);

      if (buffer.length < 8) { // Minimum size for header validation
        throw new Error('Invalid image: Buffer too small');
      }

      // Verify image format using magic numbers
      const isJPEG = buffer[0] === 0xFF && buffer[1] === 0xD8;
      const isPNG = buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47;
      const isGIF = buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38;

      if (!isJPEG && !isPNG && !isGIF) {
        throw new Error('Invalid image: Unsupported format');
      }
    } catch (bufferError) {
      console.error('Error processing image buffer:', bufferError);
      return NextResponse.json({
        error: 'Invalid image',
        message: bufferError instanceof Error ? bufferError.message : 'Error processing image'
      }, { status: 400 });
    }

    // Update user's image_data in database with error handling
    try {
      await prisma.user.update({
        where: { id: session.user.id },
        data: { image_data: buffer }
      });
    } catch (dbError) {
      console.error('Database error:', dbError);
      return NextResponse.json({
        error: 'Database error',
        message: 'Failed to save image to database'
      }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error uploading image:', error);
    return NextResponse.json({ 
      error: 'Failed to upload image',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { 
      status: 500
    });
  }
}