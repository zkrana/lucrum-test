import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../auth/[...nextauth]/route';

// Define the expected structure of a marketing content item
interface MarketingContent {
  id: string;
  size?: number | null;
  downloads: number;
  views: number;
  created_by?: number | null;
  created_at: string;
  updated_at: string;
  file_path: string | null;
  thumbnail_path: string | null;
}

export async function GET() {
  try {
    // Check authentication
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }
    console.log('📍 Starting marketing content fetch...');
    console.log('🛠️ Token:', session?.user?.accessToken);
    
    const response = await fetch('http://localhost:8000/api/rest-api/marketing/MarketingApi.php', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${session.user.accessToken}`
      }
    });

    if (!response.ok) {
      const text = await response.text();
      console.error("🚨 API Error Response:", text);
      throw new Error(text || 'Failed to fetch marketing content');
    }

    const marketingContent: MarketingContent[] = await response.json(); // Explicitly type API response

    console.log('🔍 Marketing Content Query Results:', {
      count: marketingContent.length
    });
    console.log('✨ Processing marketing content for serialization...');

    // Ensure file paths are properly prefixed with FILES_PATH
    const formatPath = (path: string | null): string | null => {
      if (!path) return null;
      if (path.startsWith('http')) return path;
      return `${process.env.FILES_PATH?.replace(/\/$/, '')}/uploads/${path.replace(/^\//, '')}`;
    };

    const serializedContent = marketingContent.map((content: MarketingContent) => ({
      ...content,
      size: content.size ? Number(content.size) : null,
      downloads: content.downloads ? Number(content.downloads) : 0,
      views: content.views ? Number(content.views) : 0,
      created_by: content.created_by ? Number(content.created_by) : null,
      file_path: formatPath(content.file_path),
      thumbnail_path: formatPath(content.thumbnail_path)
    }));

    return NextResponse.json(serializedContent);
  } catch (error) {
    // Log the full error for debugging
    console.error("❌ Error fetching marketing content:", {
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    });

    // Return appropriate error response
    if (error instanceof Error) {
      if (error.message.includes('timeout')) {
        return NextResponse.json({ error: 'Request timeout' }, { status: 504 });
      }
    }

    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}