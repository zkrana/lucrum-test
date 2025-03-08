'use client';

import { useSession } from 'next-auth/react';
import { useRouter, usePathname } from 'next/navigation';
import { signOut } from 'next-auth/react';
import Link from 'next/link';
import { useState, useEffect } from 'react';
import Image from 'next/image';

interface AuthLayoutProps {
  children: React.ReactNode;
}

export default function AuthLayout({ children }: AuthLayoutProps) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const pathname = usePathname();
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [imageKey, setImageKey] = useState<string>('');
  const [hasCompletedTraining, setHasCompletedTraining] = useState(false);

  useEffect(() => {
    const checkTrainingProgress = async () => {
      try {
        const response = await fetch('/api/training/progress', {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          credentials: 'include'
        });

        if (response.ok) {
          const progress = await response.json() as { videoId: string; completed: boolean; questionsCompleted: boolean }[];
          const completedVideos = progress.filter(video => video.completed && video.questionsCompleted);
          setHasCompletedTraining(completedVideos.length === 3);
        }
      } catch (error) {
        console.error('Error checking training progress:', error);
      }
    };

    if (session?.user) {
      checkTrainingProgress();
    }
  }, [session?.user]);

  useEffect(() => {
    // Set initial image key when component mounts
    setImageKey(Date.now().toString());
  }, []);

  useEffect(() => {
    if (status === 'unauthenticated') {
      router.push('/');
    }
  }, [status, router]);

  if (status === 'loading') {
    return (
      <div className="md:min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (status === 'unauthenticated') {
    return null;
  }

  const isApproved = session?.user?.hasDashboardAccess;
  const isAdmin = session?.user?.isAdmin;

  return (
    <div className="md:min-h-screen pb-10">
      <nav className="relative before:absolute before:content-[''] pb-4 before:h-[200px] before:w-full before:-top-[50px] before:left-0 before:bg-gradient-to-b before:from-[rgba(0,117,226,0.6)] before:to-[rgba(0,117,226,0)]">
        <div className="max-w-[1160px] bg-white relative z-12  rounded-md mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 mt-12">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center mr-[100px]">
                <Link href="/" className="text-2xl font-bold text-gray-900">
                  Lucrum
                </Link>
              </div>
              <div className="hidden lg:ml-6 lg:flex lg:space-x-8">
                {/* Navigation links with access control */}
                {!isApproved || session?.user?.status === 'pending' ? (
                  <>
                    <span className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-300 cursor-not-allowed">
                      Training
                    </span>
                    <span className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-300 cursor-not-allowed">
                      Dashboard
                    </span>
                    <span className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-300 cursor-not-allowed">
                      Marketing
                    </span>
                    <span className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-300 cursor-not-allowed">
                      CPA/Legal
                    </span>
                  </>
                ) : (
                  <>
                    {isAdmin && session?.user?.status === 'active' && (
                      <Link
                        href="/admin"
                        className={`${pathname === '/admin' ? 'border-blue-500 text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'} inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium`}
                      >
                        Admin
                      </Link>
                    )}
                    {session?.user?.status === 'active' ? (
                      <>
                        {hasCompletedTraining ? (
                          <Link
                            href="/dashboard"
                            className={`${pathname === '/dashboard' ? 'before:content-[""]  before:absolute before:bottom-0 before:left-0 before:w-[75px] before:h-[7px] before:rounded-t-[10px] before:bg-[#0075E2] before:left-[14%] before-transform -before-translate-x-1/2 before:border-[#0075E2]  text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'} w-[104px] justify-center inline-flex items-center px-1 pt-1 border-b-2 2xl:text-[20px] 2xl:leading-[28px] text-sm font-medium relative`}
                          >
                            Dashboard
                          </Link>
                        ) : (
                          <span className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-300 cursor-not-allowed">
                            Dashboard
                          </span>
                        )}
                        <Link
                          href="/training"
                          className={`${pathname === '/training' ? 'before:content-[""] before:absolute before:bottom-0 before:left-0 before:w-[75px] before:h-[7px] before:rounded-t-[10px] before:bg-[#0075E2] before:left-[14%] before-transform -before-translate-x-1/2 before:border-[#0075E2]  text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'} w-[104px] justify-center inline-flex items-center px-1 pt-1 border-b-2 text-sm 2xl:text-[20px] 2xl:leading-[28px] font-medium relative`}
                        >
                          Training
                        </Link>
                        {hasCompletedTraining ? (
                          <>
                            <Link
                              href="/marketing"
                              className={`${pathname === '/marketing' ? 'before:content-[""] before:absolute before:bottom-0 before:left-0 before:w-[75px] before:h-[7px] before:rounded-t-[10px] before:bg-[#0075E2] before:left-[14%] before-transform -before-translate-x-1/2 before:border-[#0075E2]  text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'} w-[104px] justify-center inline-flex items-center px-1 pt-1 border-b-2 text-sm 2xl:text-[20px] 2xl:leading-[28px] font-medium relative`}
                            >
                              Marketing
                            </Link>
                            <Link
                              href="/cpa-legal"
                              className={`${pathname === '/cpa-legal' ? 'before:content-[""] before:absolute before:bottom-0 before:left-0 before:w-[75px] before:h-[7px] before:rounded-t-[10px] before:bg-[#0075E2] before:left-[14%] before-transform -before-translate-x-1/2 before:border-[#0075E2]  text-gray-900' : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'} w-[104px] justify-center inline-flex items-center px-1 pt-1 border-b-2 text-sm 2xl:text-[20px] 2xl:leading-[28px] font-medium relative`}
                            >
                              CPA/Legal
                            </Link>
                          </>
                        ) : (
                          <>
                            <span className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-300 cursor-not-allowed">
                              Marketing
                            </span>
                            <span className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-300 cursor-not-allowed">
                              CPA/Legal
                            </span>
                          </>
                        )}
                      </>
                    ) : null}
                  </>
                )}
              </div>
            </div>
            <div className="flex items-center space-x-4 border-l-[7px] border-l-[#F6F6F6] pl-2">
              {!isApproved && (
                <span className="px-3 py-1 text-sm text-yellow-800 bg-yellow-100 rounded-full">
                  Pending Approval
                </span>
              )}
              <div className="relative">
                <button
                  onClick={() => setIsProfileOpen(!isProfileOpen)}
                  className="flex items-center space-x-3 focus:outline-none"
                >
                  <div className="relative w-10 h-10 rounded-full overflow-hidden bg-gray-200 border-2 border-gray-300">
                    {session?.user?.id ? (
                      <>
                        <Image
                          src={`/api/profile/image?userId=${session.user.id}${imageKey ? `&t=${imageKey}` : ''}`}
                          alt="Profile"
                          fill
                          className="object-cover"
                          onError={(e) => {
                            const target = e.target as HTMLImageElement;
                            target.style.display = 'none';
                            (target.parentElement?.querySelector('.fallback-avatar') as HTMLElement).style.display = 'flex';
                          }}
                        />
                        <div 
                          className="w-full h-full flex items-center justify-center bg-blue-500 text-white text-lg font-semibold fallback-avatar"
                          style={{ display: 'none' }}
                        >
                          {session?.user?.name?.[0]?.toUpperCase() || '?'}
                        </div>
                      </>
                    ) : (
                      <div className="w-full h-full flex items-center justify-center bg-blue-500 text-white text-lg font-semibold">
                        {session?.user?.name?.[0]?.toUpperCase() || '?'}
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col gap-1 items-start">
                    <div className='flex items-center gap-2 justify-between min-w-[120px]'>
                      <div className='text-sm font-medium text-gray-700'>{session?.user?.name || 'User'}</div>
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        className={`h-5 w-5 text-gray-500 transition-transform duration-200 ${isProfileOpen ? 'rotate-180' : ''}`}
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                        strokeWidth={2.5}
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                      </svg>
                    </div>
                    <div className='text-sm font-medium text-gray-700'>{session?.user?.email || 'User'}</div>
                  </div>
                </button>

                {isProfileOpen && (
                  <div className="absolute z-[2] md:left-0 top-[45px] -left-[10px] mt-2 w-48 rounded-md shadow-lg py-1 bg-white ring-1 ring-black ring-opacity-5">
                    {/* Mobile Navigation Links */}
                    <div className="lg:hidden border-b border-gray-200 pb-2 mb-2">
                      {session?.user?.status === 'active' && hasCompletedTraining ? (
                        <>
                          <Link
                            href="/dashboard"
                            className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                            onClick={() => setIsProfileOpen(false)}
                          >
                            Dashboard
                          </Link>
                          <Link
                            href="/training"
                            className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                            onClick={() => setIsProfileOpen(false)}
                          >
                            Training
                          </Link>
                          <Link
                            href="/marketing"
                            className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                            onClick={() => setIsProfileOpen(false)}
                          >
                            Marketing
                          </Link>
                          <Link
                            href="/cpa-legal"
                            className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                            onClick={() => setIsProfileOpen(false)}
                          >
                            CPA/Legal
                          </Link>
                        </>
                      ) : null}
                      {isAdmin && session?.user?.status === 'active' && (
                        <Link
                          href="/admin"
                          className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                          onClick={() => setIsProfileOpen(false)}
                        >
                          Admin
                        </Link>
                      )}
                    </div>
                    {/* Profile Links */}
                    <Link
                      href="/profile"
                      className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                      onClick={() => setIsProfileOpen(false)}
                    >
                      Your Profile
                    </Link>
                    <Link
                      href="/settings"
                      className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                      onClick={() => setIsProfileOpen(false)}
                    >
                      Settings
                    </Link>
                    <button
                      onClick={() => signOut({ callbackUrl: '/' })}
                      className="block w-full text-left px-4 py-2 text-sm text-red-700 hover:bg-gray-100"
                    >
                      Sign Out
                    </button>
                  </div>
                )}

              </div>
            </div>
          </div>
        </div>
      </nav>

      <div className="py-6 bg-gray-100">
        <div className="max-w-[1160px] mx-auto">
          {children}
        </div>
      </div>
    </div>
  );
}