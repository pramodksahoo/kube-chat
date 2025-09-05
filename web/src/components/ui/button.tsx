import React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cn } from '@/utils/cn';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  asChild?: boolean;
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'destructive';
  size?: 'sm' | 'md' | 'lg' | 'icon';
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    { className, variant = 'primary', size = 'md', asChild = false, type = 'button', ...props },
    ref
  ) => {
    const Comp = asChild ? Slot : 'button';

    return (
      <Comp
        className={cn(
          // Base styles
          'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
          'disabled:opacity-50 disabled:pointer-events-none',

          // Variant styles
          {
            'bg-primary-600 text-white hover:bg-primary-700':
              variant === 'primary',
            'bg-gray-100 text-gray-900 hover:bg-gray-200':
              variant === 'secondary',
            'border border-gray-300 bg-transparent hover:bg-gray-50':
              variant === 'outline',
            'hover:bg-gray-100': variant === 'ghost',
            'bg-destructive-600 text-white hover:bg-destructive-700':
              variant === 'destructive',
          },

          // Size styles
          {
            'h-8 px-3 text-xs': size === 'sm',
            'h-10 px-4': size === 'md',
            'h-11 px-8': size === 'lg',
            'h-10 w-10': size === 'icon',
          },

          className
        )}
        ref={ref}
        type={type}
        {...props}
      />
    );
  }
);

Button.displayName = 'Button';

export { Button, type ButtonProps };
