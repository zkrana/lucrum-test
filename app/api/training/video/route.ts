import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import { createReadStream, statSync } from 'fs';
import { join } from 'path';
import { Readable } from 'stream';

export async function GET(request: NextRequest) {
  try {
    // Check authentication
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    // Get video URL from query parameters
    const url = request.nextUrl.searchParams.get('url');
    if (!url) {
      return new NextResponse('Video URL is required', { status: 400 });
    }

    // Check if URL is a YouTube URL
    const isYouTubeUrl = url.match(/^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.be)\/.+/);
    if (isYouTubeUrl) {
      const videoId = url.match(/(?:youtu\.be\/|youtube\.com\/(?:embed\/|v\/|watch\?v=|watch\?.+&v=))([^&?\n]+)/)?.[1];
      if (!videoId) {
        return new NextResponse('Invalid YouTube URL', { status: 400 });
      }
      const embedUrl = `https://www.youtube.com/embed/${videoId}`;
      return NextResponse.json({ type: 'youtube', url: embedUrl });
    }

    // Ensure the URL is within the public/uploads/videos directory
    const videoPath = join(process.cwd(), url);
    if (!videoPath.startsWith(join(process.cwd(), 'public/uploads/videos'))) {
      return new NextResponse('Invalid video path', { status: 403 });
    }

    // Get video stats
    const stat = statSync(videoPath);
    const fileSize = stat.size;
    const range = request.headers.get('range');

    if (range) {
      // Handle range requests for video streaming
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunksize = end - start + 1;
      const stream = createReadStream(videoPath, { start, end });

      const headers = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': 'video/webm',
      };

      return new NextResponse(new ReadableStream({
        start(controller) {
          stream.on('data', (chunk) => controller.enqueue(chunk));
          stream.on('end', () => controller.close());
          stream.on('error', (err) => controller.error(err));
        },
      }), {
        status: 206,
        headers,
      });
    } else {
      // Handle non-range requests
      const contentType = videoPath.endsWith('.webm') ? 'video/webm' :
                         videoPath.endsWith('.mp4') ? 'video/mp4' :
                         videoPath.endsWith('.ogg') ? 'video/ogg' : 'video/mp4';

      const headers = {
        'Content-Length': fileSize,
        'Content-Type': contentType,
        'Accept-Ranges': 'bytes'
      };

      const stream = createReadStream(videoPath);
      return new NextResponse(new ReadableStream({
        start(controller) {
          stream.on('data', (chunk) => controller.enqueue(chunk));
          stream.on('end', () => controller.close());
          stream.on('error', (err) => controller.error(err));
        },
      }), {
        status: 200,
        headers,
      });
    }
  } catch (error) {
    console.error('Error streaming video:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}