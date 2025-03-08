import React, { useState } from 'react';
import { PlayIcon } from '@heroicons/react/24/solid';

interface VideoCardProps {
  title: string;
  description?: string;
  videoUrl: string;
  thumbnailUrl?: string;
  questions?: {
    id: string;
    question: string;
    options: string[];
    orderNumber: number;
    type: string;
    correctAnswer: string;
  }[];
  onVideoComplete?: () => void;
}

export default function VideoCard({ title, description, videoUrl, thumbnailUrl, questions, onVideoComplete }: VideoCardProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const videoRef = React.useRef<HTMLVideoElement>(null);

  const handleVideoClick = () => {
    setIsPlaying(true);
    if (videoRef.current) {
      videoRef.current.play();
    }
  };

  const handleVideoEnded = () => {
    if (onVideoComplete) {
      onVideoComplete();
    }
  };

  return (
    <div className="relative rounded-lg overflow-hidden shadow-lg bg-white">
      <div 
        className="relative aspect-video w-full cursor-pointer group"
        onClick={handleVideoClick}
      >
        {thumbnailUrl ? (
          <>
            <img
              src={thumbnailUrl}
              alt={title}
              className="w-full h-full object-cover"
            />
            {!isPlaying && (
              <div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-40 transition-opacity group-hover:bg-opacity-60">
                <PlayIcon className="w-16 h-16 text-white opacity-80 group-hover:opacity-100 transition-opacity" />
              </div>
            )}
          </>
        ) : (
          <>
            <video
              ref={videoRef}
              src={videoUrl}
              className="w-full h-full object-cover"
              autoPlay
              muted={!isPlaying}
              loop={!isPlaying}
              playsInline
              controls={isPlaying}
              onEnded={handleVideoEnded}
            />
            {!isPlaying && (
              <div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-40 transition-opacity group-hover:bg-opacity-60">
                <PlayIcon className="w-16 h-16 text-white opacity-80 group-hover:opacity-100 transition-opacity" />
              </div>
            )}
          </>
        )}
      </div>
      <div className="p-4">
        <h3 className="text-lg font-semibold text-gray-900 mb-2">{title}</h3>
        {description && (
          <p className="text-sm text-gray-600">{description}</p>
        )}
      </div>
    </div>
  );
}