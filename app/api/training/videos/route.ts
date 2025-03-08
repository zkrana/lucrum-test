import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';

interface ApiVideo {
  videoId: string;
  title: string;
  description: string;
  videoUrl: string;
  orderNumber: number;
  completed: number;
  questionsCompleted: number;
  updatedAt: string | null;
  questions: {
    id: string;
    question: string;
    options: string[];
    orderNumber: number;
    type: string;
    answer: string;
  }[];
}

interface FormattedVideo {
  id: string;
  title: string;
  description: string;
  videoUrl: string;
  orderNumber: number;
  completed: boolean;
  questionsCompleted: number;
  updatedAt: string | null;
  questions: {
    id: string;
    question: string;
    options: string[];
    orderNumber: number;
    type: string;
    correctAnswer: string;
  }[];
}

export async function GET(request: Request) {
  try {
    // Check authentication
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    // Fetch training videos from PHP backend
    const response = await fetch('http://localhost:8000/api/rest-api/training/TrainingApi.php', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${session.user.accessToken}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      // Check if response is HTML (indicating server error)
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('text/html')) {
        throw new Error('Received HTML response instead of JSON. The server might be misconfigured.');
      }

      // Try to parse error as JSON, fallback to status text if not possible
      let errorMessage;
      try {
        const error = await response.json();
        errorMessage = error.message || error.error || 'Failed to fetch training videos';
      } catch {
        errorMessage = response.statusText || 'Failed to fetch training videos';
      }
      throw new Error(errorMessage);
    }

    // Safely parse JSON response
    let videos: ApiVideo[];
    try {
      videos = await response.json();
    } catch (parseError) {
      console.error('Error parsing videos response:', parseError);
      throw new Error('Invalid JSON response from server');
    }

    // Format the response
    const formattedVideos: FormattedVideo[] = videos.map((video) => ({
      id: video.videoId,
      title: video.title,
      description: video.description,
      videoUrl: video.videoUrl,
      orderNumber: video.orderNumber,
      completed: video.completed === 1,
      questionsCompleted: video.questionsCompleted,
      updatedAt: video.updatedAt,
      questions: video.questions?.map(q => ({
        id: q.id,
        question: q.question,
        options: Array.isArray(q.options) ? q.options : typeof q.options === 'string' ? JSON.parse(q.options) : [],
        orderNumber: q.orderNumber,
        type: q.type,
        correctAnswer: q.answer
      })) || []
    }));

    return NextResponse.json(formattedVideos);
  } catch (error) {
    console.error('Error fetching training videos:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal Server Error' },
      { status: 500 }
    );
  }
}