'use client';

import { useSession } from 'next-auth/react';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { signOut } from 'next-auth/react';

interface TrainingProgress {
  videoId: string;
  completed: boolean;
  questionsCompleted?: boolean;
}

export default function DashboardPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (status === 'authenticated' && session?.user?.status === "pending") {
      setLoading(false);
      return;
    }

    if (status === 'authenticated') {
      if (!session?.user?.hasDashboardAccess) {
        router.push('/training');
        setLoading(false);
        return;
      }
      setLoading(false);
    }
  }, [status, router, session]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (status === 'authenticated' && session?.user && !session.user.hasDashboardAccess) {
    return (
      <main className="min-h-screen p-8 bg-gray-50">
        <div className="max-w-7xl mx-auto">
          <div className="bg-white rounded-lg shadow-lg p-6 mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-4">Complete Training Required</h1>
            <p className="text-gray-600 mb-6">Please complete all training videos before accessing the dashboard.</p>
            <button
              onClick={() => router.push('/training')}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors mr-4"
            >
              Go to Training
            </button>
            <button
              onClick={() => signOut({ callbackUrl: '/' })}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors"
            >
              Sign Out
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-[calc(100vh-153px)] flex justify-center items-center bg-white p-8 relative z-1 rounded-[20px]">
      <div className="max-w-7xl mx-auto h-fit">
        <div className="lg:w-[560px] w-fit max-w-2xl bg-[#F4F4F4] border-[#B9B9B9] rounded-[8px] shadow-xl p-8 transform transition-all duration-300 hover:scale-[1.02] hover:shadow-2xl">
          <div className="space-y-6">
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-blue-100 rounded-full">
                <svg className="w-6 h-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                </svg>
              </div>
              <div>
                <h2 className="text-2xl font-bold text-gray-900">Share and Earn</h2>
                <p className="text-gray-600">Invite your friends with this referral link</p>
              </div>
            </div>

            <div className="relative">
              <div className="flex items-center space-x-3 p-4 bg-white rounded-lg border border-gray-200 shadow-sm">
                <input
                  type="text"
                  readOnly
                  value={`${window.location.origin}?ref=${session?.user?.id}`}
                  className="w-full bg-transparent text-gray-600 focus:outline-none"
                />
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(`${window.location.origin}?ref=${session?.user?.id}`);
                    const button = document.getElementById('copyButton');
                    if (button) {
                      button.innerHTML = '<span class="flex items-center"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>Copied!</span>';
                      setTimeout(() => {
                        button.innerHTML = 'Copy';
                      }, 2000);
                    }
                  }}
                  id="copyButton"
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transform hover:scale-105"
                >
                  Copy
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-2 text-sm text-gray-500">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p>Your unique referral link will be tracked automatically</p>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}