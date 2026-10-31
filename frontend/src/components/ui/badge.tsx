import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset',
  {
    variants: {
      variant: {
        default: 'bg-accent/15 text-accent-soft ring-accent/40',
        secondary: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
        success: 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/40',
        warning: 'bg-amber-500/15 text-amber-400 ring-amber-500/40',
        destructive: 'bg-red-500/15 text-red-400 ring-red-500/40',
        outline: 'border border-slate-600/60 text-slate-400',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
