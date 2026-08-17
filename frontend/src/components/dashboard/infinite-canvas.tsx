"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import { ZoomIn, ZoomOut, RotateCcw } from "lucide-react";

export function InfiniteCanvas() {
  const targetOffset = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const currentOffset = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const targetScale = useRef<number>(1);
  const currentScale = useRef<number>(1);

  const [, setRenderTrigger] = useState<number>(0);
  const isDragging = useRef<boolean>(false);
  const dragStart = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const rafId = useRef<number | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Smooth 60fps Physics & Lerp Animation Loop
  useEffect(() => {
    const animate = () => {
      // Linear interpolation factor for ultra-smooth buttery inertia (0.15 = silky smooth)
      const lerp = 0.14;

      const dx = targetOffset.current.x - currentOffset.current.x;
      const dy = targetOffset.current.y - currentOffset.current.y;
      const ds = targetScale.current - currentScale.current;

      const isMoving = Math.abs(dx) > 0.05 || Math.abs(dy) > 0.05 || Math.abs(ds) > 0.001;

      if (isMoving) {
        currentOffset.current.x += dx * lerp;
        currentOffset.current.y += dy * lerp;
        currentScale.current += ds * lerp;
        setRenderTrigger((n) => (n + 1) % 100000);
      }

      rafId.current = requestAnimationFrame(animate);
    };

    rafId.current = requestAnimationFrame(animate);
    return () => {
      if (rafId.current) cancelAnimationFrame(rafId.current);
    };
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 0 || e.button === 1) {
      isDragging.current = true;
      dragStart.current = {
        x: e.clientX - targetOffset.current.x,
        y: e.clientY - targetOffset.current.y,
      };
    }
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isDragging.current) return;
    targetOffset.current = {
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y,
    };
  }, []);

  const handleMouseUp = useCallback(() => {
    isDragging.current = false;
  }, []);

  // Smooth two-finger trackpad pan & mouse wheel navigation
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();

    if (e.ctrlKey || e.metaKey) {
      // Zoom on pinch / Ctrl+wheel
      const zoomDelta = e.deltaY < 0 ? 1.08 : 0.92;
      targetScale.current = Math.min(Math.max(targetScale.current * zoomDelta, 0.4), 2.5);
    } else {
      // Soft calibrated scroll speed for natural 2D canvas navigation
      const scrollSpeed = 0.85;
      targetOffset.current = {
        x: targetOffset.current.x - e.deltaX * scrollSpeed,
        y: targetOffset.current.y - e.deltaY * scrollSpeed,
      };
    }
  }, []);

  const resetView = () => {
    targetOffset.current = { x: 0, y: 0 };
    targetScale.current = 1;
  };

  const gridSize = 24 * currentScale.current;

  return (
    <div
      ref={containerRef}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      onWheel={handleWheel}
      className={`w-full h-full relative overflow-hidden bg-[#0A0A0E] select-none ${
        isDragging.current ? "cursor-grabbing" : "cursor-grab"
      }`}
    >
      {/* Pure Infinite Minimal Dotted Grid Canvas Layer (No Extra Shapes) */}
      <div
        className="absolute inset-0 pointer-events-none will-change-transform"
        style={{
          backgroundImage: `radial-gradient(circle, rgba(255, 255, 255, 0.08) 1.2px, transparent 1.2px)`,
          backgroundSize: `${gridSize}px ${gridSize}px`,
          backgroundPosition: `${currentOffset.current.x}px ${currentOffset.current.y}px`,
        }}
      />

      {/* Floating Minimal Controls Widget at Bottom Left */}
      <div className="absolute bottom-4 left-4 z-20 flex items-center gap-1.5 bg-[#121216]/80 backdrop-blur-md border border-white/10 p-1.5 rounded-xl shadow-lg pointer-events-auto">
        <button
          onClick={() => {
            targetScale.current = Math.min(targetScale.current * 1.15, 2.5);
          }}
          className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-white/10 transition-colors"
          title="Zoom In"
        >
          <ZoomIn className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => {
            targetScale.current = Math.max(targetScale.current * 0.85, 0.4);
          }}
          className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-white/10 transition-colors"
          title="Zoom Out"
        >
          <ZoomOut className="w-3.5 h-3.5" />
        </button>
        <span className="text-[10px] font-mono text-neutral-400 px-1">
          {Math.round(currentScale.current * 100)}%
        </span>
        <button
          onClick={resetView}
          className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-white/10 transition-colors"
          title="Reset Canvas View"
        >
          <RotateCcw className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
