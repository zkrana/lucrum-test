'use client';

import { useSession } from 'next-auth/react';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { signOut } from 'next-auth/react';
import React from 'react';

interface TrainingVideo {
  id: string;
  title: string;
  description: string | null;
  videoUrl: string;
  orderNumber: number;
  questions: VideoQuestion[];
}

interface VideoQuestion {
  id: string;
  question: string;
  options: string[];
  correctAnswer?: string;
  type?: string;
  orderNumber?: number;
}

interface VideoProgress {
  videoId: string;
  completed: boolean;
  questionsCompleted: number;
}

export default function TrainingPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [videos, setVideos] = useState<TrainingVideo[]>([]);
  const [progress, setProgress] = useState<VideoProgress[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentVideoIndex, setCurrentVideoIndex] = useState(0);
  const [showQuestions, setShowQuestions] = useState(false);
  const [selectedAnswers, setSelectedAnswers] = useState<number[]>([]);
  const [incorrectAttempt, setIncorrectAttempt] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleQuizSubmission = async () => {
    const allCorrect = currentVideo.questions.every(
      (q, i) => {
        const correctIndex = q.correctAnswer ? q.correctAnswer.charCodeAt(0) - 'A'.charCodeAt(0) : -1;
        return selectedAnswers[i] === correctIndex;
      }
    );
    
    if (!allCorrect) {
      setIncorrectAttempt(true);
      return;
    }
    
    if (allCorrect && currentVideo.questions.length > 0) {
      setIncorrectAttempt(false);
      
      try {
        // Update progress in the database
        const response = await fetch('/api/training/progress/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            videoId: currentVideo.id,
            completed: true,
            questionsCompleted: true
          }),
        });
  
        const result = await response.json();
  
        // Fetch the updated progress
        const updatedProgressResponse = await fetch('/api/training/progress');
        if (updatedProgressResponse.ok) {
          const updatedProgressData = await updatedProgressResponse.json();
          setProgress(updatedProgressData);
  
          setShowQuestions(false);
  
          // Check if this was the last video and all questions are completed
          if (result.hasDashboardAccess && currentVideoIndex === videos.length - 1) {
            // Show final completion message
            const finalMessage = document.createElement('div');
            finalMessage.className = 'fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50';
            finalMessage.innerHTML = `
              <div class="bg-white p-8 rounded-lg shadow-xl max-w-md w-full mx-4">
                <div class="text-center" style="display: flex; flex-direction: column; gap: 10px;">
                  
                <div style="margin: 0 auto; display: block;" className="mx-auto block">
                <svg width="86" height="86" viewBox="0 0 86 86" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M43 0.125C34.5201 0.125 26.2307 2.63958 19.1799 7.35074C12.1292 12.0619 6.63379 18.7581 3.38868 26.5924C0.143577 34.4268 -0.705491 43.0476 0.94885 51.3645C2.60319 59.6814 6.68664 67.321 12.6828 73.3172C18.679 79.3134 26.3186 83.3968 34.6355 85.0512C42.9525 86.7055 51.5732 85.8564 59.4076 82.6113C67.242 79.3662 73.9381 73.8708 78.6493 66.8201C83.3604 59.7693 85.875 51.4799 85.875 43C85.875 31.6288 81.3578 20.7234 73.3172 12.6828C65.2766 4.64217 54.3712 0.125 43 0.125ZM36.875 60.1194L21.5625 44.8069L26.4319 39.9375L36.875 50.3806L59.5681 27.6875L64.4559 32.5446L36.875 60.1194Z" fill="#0075E2"/>
                    </svg>
                </div>

                  <h2 class="text-2xl font-bold text-gray-900 mb-2">Congratulations!</h2>
                  <p class="text-gray-600 mb-6">You've successfully completed all training videos! You now have full access to the dashboard.</p>
                  <div class="flex items-center justify-center">
                    <button class="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors" onclick="window.location.href='/dashboard'">Go to Dashboard</button>
                  </div>
                </div>
              </div>
            `;
            document.body.appendChild(finalMessage);
            return;
          }
  
          // Move to next video if available
          if (currentVideoIndex < videos.length - 1) {
            setCurrentVideoIndex(currentVideoIndex + 1);
          }
        }
      } catch (error) {
        console.error('Error updating progress:', error);
        setShowQuestions(false);
      }
    } else {
      setIncorrectAttempt(true);
      setSelectedAnswers([]);
    }
  };

  useEffect(() => {
    if (videos.length > 0) {
      // Log correct answers for debugging
      videos.forEach(video => {
        console.log(`Video ${video.title} - Questions:`);
        video.questions.forEach(question => {
          console.log(`Question: ${question.question}`);
          console.log(`Correct Answer: ${question.correctAnswer}`);
          console.log(`Options:`, question.options);
          console.log('---');
        });
      });
    }
  }, [videos]);

  useEffect(() => {
    if (status === 'authenticated' && session?.user?.status === "pending") {
      setLoading(false);
      return;
    }


    if (status === 'authenticated' && session?.user && !session.user.hasDashboardAccess) {
      setLoading(false);
      return;
    }

    const fetchData = async () => {
      try {
        const [videosResponse, progressResponse] = await Promise.all([
          fetch('/api/training/videos', {
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include'
          }),
          fetch('/api/training/progress', {
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include'
          })
        ]);
    
        if (!videosResponse.ok || !progressResponse.ok) {
          throw new Error('Failed to fetch data');
        }
    
        const videosData = await videosResponse.json();
        const progressData = await progressResponse.json();
    
        console.log("Fetched User Training Progress on Page Load:", progressData);
        progressData.forEach((p: VideoProgress) => {
          console.log(`Video ID: ${p.videoId}, Completed: ${p.completed}`);
        });
    
        const sortedVideos = videosData.sort((a: TrainingVideo, b: TrainingVideo) =>
          a.orderNumber - b.orderNumber
        );
    
        setVideos(sortedVideos);
        setProgress(progressData);
    
        const firstIncompleteIndex = progressData.findIndex((p: VideoProgress) => !p.completed || !p.questionsCompleted);
        setCurrentVideoIndex(firstIncompleteIndex === -1 ? 0 : firstIncompleteIndex);
    
      } catch (error) {
        setError('Failed to load training videos. Please try again.');
        console.error('Error fetching data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [status, session, router]);

  const handleVideoSelect = (index: number) => {
    // Only allow selecting videos that are unlocked
    const previousVideosCompleted = index === 0 || progress.slice(0, index).every(
      (p) => p.completed && p.questionsCompleted
    );
    const currentVideoProgress = progress.find((p) => p.videoId === videos[index]?.id);
    const isVideoAccessible = previousVideosCompleted || (currentVideoProgress?.completed && currentVideoProgress?.questionsCompleted);

    if (isVideoAccessible) {
      setCurrentVideoIndex(index);
      setShowQuestions(false);
      setSelectedAnswers([]);
      setIncorrectAttempt(false);
    }
  };

  useEffect(() => {
    if (videos.length > 0) {
      // Log correct answers for debugging
      videos.forEach(video => {
        console.log(`Video ${video.title} - Questions:`);
        video.questions.forEach(question => {
          console.log(`Question: ${question.question}`);
          console.log(`Correct Answer: ${question.correctAnswer}`);
          console.log(`Options:`, question.options);
          console.log('---');
        });
      });
    }
  }, [videos]);

  if (loading) {
    return (
      <div className="flex items-center justify-center md:min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center md:min-h-screen">
        <div className="text-red-500">{error}</div>
      </div>
    );
  }


  if (!session?.user?.hasDashboardAccess || session?.user?.status === "pending") {
    return (
      <div className="md:min-h-screen flex flex-col items-center justify-center bg-gray-50">
        <div className="max-w-md w-full mx-auto p-8 bg-white rounded-xl shadow-lg text-center">
          <div className="mb-6">
            <svg
              className="mx-auto h-16 w-16 text-gray-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Thank you for signing up!</h2>
          <p className="text-gray-600 mb-8">We're reviewing your registration and will notify you  via <span className='text-[#0075E2]'>email</span> once your access is approved.</p>
          <button
            onClick={() => signOut()}
            className="w-full flex justify-center py-3 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-[#0075E2] hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-200"
          >
            Sign Out
          </button>
        </div>
      </div>
    );
  }

  const currentVideo = videos[currentVideoIndex];

  return (
    <div className="w-full min-h-screen bg-gray-100">
      {/* Progress Bar */}
      <div className="w-full p-4">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-lg font-semibold text-gray-700">Learning in Progress: {Math.round((progress.filter(p => p.completed && p.questionsCompleted).length / videos.length) * 100)}%</h3>
          </div>
          <div className="w-full h-[15px] bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-[15px] bg-[#0075E2] rounded-full transition-all duration-300"
              style={{
                width: `${(progress.filter(p => p.completed && p.questionsCompleted).length / videos.length) * 100}%`
              }}
            />
          </div>
          {/* <div className="flex justify-between mt-2">
            {videos.map((video, index) => {
              const videoProgress = progress.find(p => p.videoId === video.id);
              const isCompleted = videoProgress?.completed && videoProgress?.questionsCompleted;
              const isCurrent = index === currentVideoIndex;
              
              return (
                <div
                  key={video.id}
                  className={`w-8 h-8 rounded-full flex items-center justify-center ${isCompleted ? 'bg-blue-500 text-white' : isCurrent ? 'bg-blue-100 border-2 border-blue-500' : 'bg-gray-200'}`}
                >
                  {isCompleted ? (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <span className="text-sm">{index + 1}</span>
                  )}
                </div>
              );
            })}
          </div> */}
        </div>
      </div>
     <div className='flex flex-col lg:flex-row lg:mt-8 mt-4'>
       {/* Left side - Video Player or Quiz */}
       <div className="flex-1 rounded-[20px] p-4 !pt-0 lg:p-6 !pl-0">
        {currentVideo && (
          <div className="bg-white rounded-lg lg:rounded-[20px] shadow-lg p-6">
            {!showQuestions ? (
              <>
                <div className="aspect-w-16 aspect-h-9">
                  {currentVideo.videoUrl.includes('youtube.com') ? (
                    <iframe
                      src={`${currentVideo.videoUrl.includes('watch?v=') ? 
                        currentVideo.videoUrl.replace('watch?v=', 'embed/') : 
                        currentVideo.videoUrl}?enablejsapi=1`}
                      className="w-full h-[200px] sm:h-[300px] md:h-[400px] lg:h-[500px] rounded"
                      allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                      allowFullScreen
                      loading="lazy"
                      referrerPolicy="strict-origin"
                      id="youtube-player"
                      onLoad={() => {
                        // Load YouTube IFrame API if not already loaded
                        if (!(window as any).YT) {
                          const tag = document.createElement('script');
                          tag.src = 'https://www.youtube.com/iframe_api';
                          const firstScriptTag = document.getElementsByTagName('script')[0];
                          firstScriptTag.parentNode?.insertBefore(tag, firstScriptTag);
                        }

                        // Initialize player when API is ready
                        const initPlayer = () => {
                          const player = new (window as any).YT.Player('youtube-player', {
                            events: {
                              onReady: (event: any) => {
                                // Store player instance for later use
                                (window as any).ytPlayer = event.target;
                              },
                              onStateChange: async (event: any) => {
                                // Video ended
                                if (event.data === (window as any).YT.PlayerState.ENDED) {
                                  try {
                                    const response = await fetch('/api/training/progress/update', {
                                      method: 'POST',
                                      headers: {
                                        'Content-Type': 'application/json',
                                      },
                                      body: JSON.stringify({
                                        videoId: currentVideo.id,
                                        completed: true,
                                        questionsCompleted: false
                                      })
                                    });
                                    
                                    if (response.ok) {
                                      // Update local progress state
                                      const updatedProgress = progress.map(p =>
                                        p.videoId === currentVideo.id
                                          ? { ...p, completed: true }
                                          : p
                                      );
                                      setProgress(updatedProgress);
                                      
                                      // Show questions immediately after video ends
                                      setShowQuestions(true);
                                      setSelectedAnswers([]);
                                      setIncorrectAttempt(false);
                                    }
                                  } catch (error) {
                                    console.error('Error updating video progress:', error);
                                  }
                                }
                              }
                            }
                          });
                        };
                        
                        // Call initPlayer when YT API is ready
                        if ((window as any).YT && (window as any).YT.Player) {
                          initPlayer();
                        } else {
                          (window as any).onYouTubeIframeAPIReady = initPlayer;
                        }
                      }}
                    />
                  ) : (
                    <video
                      src={currentVideo.videoUrl}
                      className="w-full h-[200px] sm:h-[300px] md:h-[400px] lg:h-[500px] rounded"
                      controls

                      onEnded={() => {
                        setShowQuestions(true);
                        // Mark video as completed
                        fetch('/api/training/progress/update', {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                          },
                          body: JSON.stringify({
                            videoId: currentVideo.id,
                            completed: true,
                            questionsCompleted: false
                          })
                        });
                      }}
                    />
                  )}
                </div>
                <div className="mt-6 p-4 bg-gray-50 rounded-lg flex justify-between items-start">
                  <div className="flex items-center space-x-4">
                    <div className="p-3 bg-blue-100 rounded-lg">
                      <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <div>
                      <h2 className="text-2xl font-bold mb-2">{currentVideo.title}</h2>
                      {/* {currentVideo.description && (
                        <p className="text-gray-600">{currentVideo.description}</p>
                      )} */}
                    </div>
                  </div>
                  {incorrectAttempt && (
                    <button
                      onClick={() => {
                        setShowQuestions(false);
                        setIncorrectAttempt(false);
                        setSelectedAnswers([]);
                      }}
                      className="flex items-center space-x-2 text-blue-600 hover:text-blue-700 transition-colors"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                      <span>Rewatch Video</span>
                    </button>
                  )}
                </div>
              </>
            ) : (
              <div className="space-y-6">
                <h2 className="text-2xl font-bold mb-4">Quiz for {currentVideo.title}</h2>
                {currentVideo.questions.map((question, qIndex) => {
                  const correctIndex = question.correctAnswer ? question.correctAnswer.charCodeAt(0) - 'A'.charCodeAt(0) : -1;
                  const videoProgress = progress.find((p) => p.videoId === currentVideo.id);
                  const isQuizCompleted = videoProgress?.questionsCompleted === 2;
                  const isAnswerSubmitted = incorrectAttempt || isQuizCompleted;
                  
                  return (
                    <div key={question.id} className="space-y-4">
                      <p className="font-medium">{question.question}</p>
                      <div className="space-y-2">
                        {question.options.map((option, oIndex) => (
                          <label
                            key={oIndex}
                            className={`flex items-center w-full p-4 rounded-xl border-2 transition-all duration-300 ease-in-out transform hover:scale-[1.02] ${isAnswerSubmitted && oIndex === correctIndex && selectedAnswers[qIndex] === correctIndex ? 'bg-green-50 border-green-500 shadow-green-100' : selectedAnswers[qIndex] === oIndex ? 'bg-blue-50 border-blue-500 shadow-blue-100' : 'border-gray-200 hover:bg-gray-50 hover:border-blue-300'} ${isQuizCompleted ? 'cursor-not-allowed opacity-75' : 'cursor-pointer'} relative shadow-sm hover:shadow-md`}
                          >
                            <div className="relative">
                              <input
                                type="radio"
                                name={`question-${qIndex}`}
                                value={oIndex}
                                checked={selectedAnswers[qIndex] === oIndex}
                                onChange={() => {
                                  if (!isQuizCompleted) {
                                    const newAnswers = [...selectedAnswers];
                                    newAnswers[qIndex] = oIndex;
                                    setSelectedAnswers(newAnswers);
                                  }
                                }}
                                disabled={isQuizCompleted}
                                className="absolute opacity-0 w-6 h-6"
                              />
                              <div className={`w-6 h-6 rounded-full border-2 mr-4 flex items-center justify-center transition-all duration-200 ${selectedAnswers[qIndex] === oIndex ? 'border-blue-500 bg-blue-500' : 'border-gray-300'}`}>
                                {selectedAnswers[qIndex] === oIndex && (
                                  <div className="w-2 h-2 rounded-full bg-white" />
                                )}
                              </div>
                            </div>
                            <span className="flex-grow text-base">{option}</span>
                            {isAnswerSubmitted && oIndex === correctIndex && (
                              <svg className="w-6 h-6 text-green-500 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                              </svg>
                            )}
                          </label>
                        ))}
                      </div>
                    </div>
                  );
                })}
                {selectedAnswers.length === currentVideo.questions.length && !progress.find(p => p.videoId === currentVideo.id)?.questionsCompleted && (
                  <div className="space-y-4">
                    <button
                      onClick={handleQuizSubmission}
                      className="w-full py-3 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                    >
                      Submit Answers
                    </button>
                
                    {incorrectAttempt && (
                      <div className="p-4 bg-red-50 border border-red-200 rounded-lg mt-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center">
                            <svg className="w-5 h-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <p className="text-red-700 font-medium">Please try again. Some answers were incorrect.</p>
                          </div>
                          <button
                            onClick={() => {
                              setShowQuestions(false);
                              setIncorrectAttempt(false);
                              setSelectedAnswers([]);
                            }}
                            className="flex items-center space-x-2 text-blue-600 hover:text-blue-700 transition-colors"
                          >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                            </svg>
                            <span>Rewatch Video</span>
                          </button>
                        </div>
                      </div>
                    )}
                

                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Right side - Video List */}
      <div className="w-full lg:w-96 bg-white lg:border-l border-t lg:border-t-0 border-gray-200 p-4 lg:p-6 overflow-y-auto rounded-lg lg:rounded-[20px]">
        <h3 className="text-xl font-bold mb-6">Training Videos</h3>
        <div className="space-y-4">
          {videos.map((video, index) => {
            const videoProgress = progress.find((p) => p.videoId === video.id);
            const isCompleted = videoProgress?.completed && videoProgress?.questionsCompleted;
            const previousVideoProgress = index > 0 ? progress.find(p => p.videoId === videos[index - 1]?.id) : null;
            const isLocked = index > 0 && (!previousVideoProgress?.completed || !previousVideoProgress?.questionsCompleted);
            const isCurrent = index === currentVideoIndex;
        
            // Calculate overall progress percentage
            const completedVideos = progress.filter(p => p.completed && p.questionsCompleted).length;
            const totalVideos = videos.length;
            const progressPercentage = Math.round((completedVideos / totalVideos) * 100);
        
            return (
              <button
                key={video.id}
                onClick={() => !isLocked && handleVideoSelect(index)}
                disabled={isLocked}
                className={`w-full text-left p-4 rounded-lg transition-all ${isCurrent ? 'bg-blue-50 border-2 border-blue-500' : 'border border-gray-200'} ${isLocked ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-50'}`}
              >
                <div className="flex items-center justify-between">
                  <div className="space-y-2 w-full">
                    <p className="font-medium">{video.title}</p>
                    <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-300 ${isCompleted ? 'bg-green-500' : 'bg-blue-500'}`}
                        style={{ width: isCompleted ? '100%' : '0%' }}
                      />
                    </div>

                  </div>
                  <div className="flex items-center space-x-2">
                    {isCompleted && (
                      <svg className="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                    {isLocked && !isCompleted && (
                      <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                    )}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
     </div>
    </div>
  );
}
