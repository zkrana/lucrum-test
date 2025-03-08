import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../../auth/[...nextauth]/route';

export async function POST(request: Request) {
  try {
    // Authenticate user
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    // Parse request body
    const { videoId, completed, questionsCompleted } = await request.json();

    // Normalize `questionsCompleted`
    let normalizedQuestionsCompleted = questionsCompleted;
    if (typeof questionsCompleted === 'boolean') {
      normalizedQuestionsCompleted = questionsCompleted ? 2 : 0;
    }

    // Validate request data
    if (!videoId || typeof completed !== 'boolean' || typeof normalizedQuestionsCompleted !== 'number' || normalizedQuestionsCompleted < 0 || normalizedQuestionsCompleted > 2) {
      return new NextResponse('Invalid request body. questionsCompleted must be a number between 0 and 2', { status: 400 });
    }

    // Send request to PHP API
    const phpApiUrl = 'http://localhost:8000/api/rest-api/training/TrainingApi.php';

    const response = await fetch(phpApiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${session.user.accessToken}`,
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        videoId,
        completed,
        questionsCompleted: normalizedQuestionsCompleted,
      }),
    });

    // Handle response
    if (!response.ok) {
      // Try to parse error response as JSON first
      let errorMessage;
      try {
        const errorData = await response.json();
        errorMessage = errorData.message || errorData.error || 'Failed to update training progress';
      } catch {
        // If JSON parsing fails, use text response
        errorMessage = await response.text();
      }
      return NextResponse.json(
        { error: errorMessage },
        { status: response.status }
      );
    }

    const data = await response.json();
    return NextResponse.json(data);

  } catch (error) {
    console.error('Error updating training progress:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal Server Error' },
      { status: 500 }
    );
  }
}