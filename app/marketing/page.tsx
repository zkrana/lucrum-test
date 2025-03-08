'use client';

import Image from 'next/image';
import { useEffect, useState } from 'react';

interface MarketingContent {
  id: string;
  title: string;
  description: string;
  type: 'pdf' | 'promotional' | 'video';
  file_path: string;
  videoType?: 'youtube' | 'upload';
  downloads?: number;
  views?: number;
  created_at: string;
}

export default function MarketingPage() {
  const [marketingCards, setMarketingCards] = useState<MarketingContent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedContent, setSelectedContent] = useState<MarketingContent | null>(null);

  useEffect(() => {
    const fetchMarketingContent = async () => {
      try {
        const response = await fetch('/api/marketing');
        const data = await response.json();
        
        if (!response.ok) {
          const errorMessage = data?.error || 'Failed to fetch marketing content';
          throw new Error(errorMessage);
        }
        
        if (!Array.isArray(data)) {
          console.error('Invalid API response format:', data);
          throw new Error('Received invalid data format from server');
        }
        
        setMarketingCards(data);
      } catch (error) {
        console.error('Error fetching marketing content:', error);
        setError(error instanceof Error ? error.message : 'Failed to load marketing content. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchMarketingContent();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-red-500 text-center">
          <p>{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  const renderCard = (content: MarketingContent) => {
    const commonCardClasses = "bg-white rounded-[20px] p-2 shadow-lg overflow-hidden transform transition duration-300 hover:scale-105";

    switch (content.type) {
      case 'pdf':
        return (
          <div className={commonCardClasses}>
            <div className="relative h-48 rounded-t-[20px] bg-gray-50 flex items-center justify-center group">
              <div className="text-gray-400 group-hover:text-gray-500 transition-colors">
                <svg className="w-20 h-20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <button
                onClick={() => setSelectedContent(content)}
                className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-0 group-hover:bg-opacity-30 transition-all duration-300"
              >
                <div className="w-12 h-12 rounded-full bg-white shadow-lg flex items-center justify-center transform scale-0 group-hover:scale-100 transition-transform duration-300">
                  <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                </div>
              </button>
            </div>
            <CardContent content={content} />
          </div>
        );

      case 'promotional':
        return (
          <div className={commonCardClasses}>
            <div className="relative h-48 rounded-t-[20px] overflow-hidden ">
              <div className="relative w-full h-full ">
                {content.file_path && content.file_path.trim() !== "" ? (
                  <div className="relative w-full h-full rounded-t-[20px]">
                    <Image
                      src={content.file_path}
                      alt={content.title}
                      fill
                      className="object-cover"
                    />
                  </div>
                ) : (
                  <div className="w-full h-full flex items-center justify-center bg-gray-200">
                    <svg
                      className="w-12 h-12 text-gray-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"
                      />
                    </svg>
                  </div>
                )}
              </div>
            </div>
            <CardContent content={content} />
          </div>
        );

      case 'video':
        return (
          <div className={commonCardClasses}>
            <div className="relative h-48 group overflow-hidden rounded-t-[20px]">
            {content.file_path && content.file_path.trim() !== "" ? (
                <div className="relative w-full h-full">
                  <img
                    src={content.file_path}
                    alt={content.title}
                    className="object-cover w-full h-full"
                    onError={(e) => {
                      const target = e.target as HTMLImageElement;
                      target.style.display = 'none';
                      const fallback = target.parentElement?.querySelector('.fallback-image');
                      if (fallback instanceof HTMLElement) {
                        fallback.style.display = 'flex';
                      }
                    }}
                  />
                  
                  {/* Fallback SVG when image fails */}
                  <div 
                    className="w-full h-full flex items-center justify-center bg-gray-200 fallback-image"
                    style={{ display: 'none' }}
                  >
                    <svg
                      className="w-12 h-12 text-gray-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"
                      />
                    </svg>
                  </div>
                </div>
              ) : (
                <div className="w-full h-full flex items-center justify-center bg-gray-200">
                  <svg
                    className="w-12 h-12 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"
                    />
                  </svg>
                </div>
              )}
              <div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-0 group-hover:bg-opacity-30 transition-all duration-300">
                <button
                  onClick={() => setSelectedContent(content)}
                  className="w-16 h-16 rounded-full bg-white shadow-lg flex items-center justify-center transform scale-0 group-hover:scale-100 transition-transform duration-300"
                >
                  <svg className="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </button>
              </div>
            </div>
            <CardContent content={content} />
          </div>
        );

      default:
        return null;
    }
  };

  const CardContent = ({ content }: { content: MarketingContent }) => (
    <div className="p-6">
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-xl font-semibold text-[#0175E1] line-clamp-2">{content.title}</h3>
        <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium capitalize
          ${content.type === 'pdf' ? 'bg-blue-100 text-blue-800' : 
            content.type === 'promotional' ? 'bg-green-100 text-green-800' : 
            'bg-purple-100 text-purple-800'}`}
        >
          {content.type}
          {content.type === 'video' && content.videoType && (
            <span className="ml-1 text-xs">({content.videoType})</span>
          )}
        </span>
      </div>
      <p className="text-gray-600 line-clamp-3 mb-4">{content.description}</p>
      <div className="flex justify-between items-center text-sm text-gray-500 border-t border-gray-100 pt-4">
        <span>{new Date(content.created_at).toLocaleDateString()}</span>
        <div className="flex items-center space-x-4">
          {content.views !== undefined && (
            <span className="flex items-center">
              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              {content.views}
            </span>
          )}
          {content.downloads !== undefined && (
            <span className="flex items-center">
              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              {content.downloads}
            </span>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen">
      <div className="max-w-7xl mx-auto">
        <div className="text-left mb-4 py-2">
          <h1 className="pl-2 text-[26px] uppercase font-bold bg-gradient-to-r from-[#0175E2] to-transparent text-white rounded-[10px] w-full mb-4 relative block">
            Marketing
          </h1>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {marketingCards.map((content, index) => (
            <div key={content.id || `marketing-card-${index}`}>
              {renderCard(content)}
            </div>
          ))}
        </div>
      </div>

      {selectedContent && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-2 w-full max-w-4xl max-h-[90vh] overflow-auto">
            <div className="flex justify-end mb-4">
              <button
                onClick={() => setSelectedContent(null)}
                className="text-gray-500 hover:text-gray-700"
              >
                Close
              </button>
            </div>
            {selectedContent.type === 'pdf' ? (


<iframe
                src={selectedContent.file_path}
                className="w-full h-[80vh]"
                title="PDF Viewer"
              />
            ) : selectedContent.type === 'video' ? (
              <div className="aspect-w-16 aspect-h-9">
                {selectedContent.videoType === 'youtube' ? (
                  <iframe
                    src={selectedContent.videoType === 'youtube' ? selectedContent.file_path : selectedContent.file_path}
                    className="w-full h-full"
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                    allowFullScreen
                  />
                ) : (
                  <video
                    src={selectedContent.file_path}
                    controls
                    className="w-full h-full"
                  />
                )}
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}