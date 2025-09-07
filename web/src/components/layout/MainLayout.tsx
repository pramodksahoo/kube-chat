import React, { useState } from 'react';
import { cn } from '@/utils/cn';
import ChatLayout from '@/components/chat/ChatLayout';
import { DemoDashboard } from '@/components/dashboard/DemoDashboard';
import { ComplianceDashboard } from '@/components/compliance/ComplianceDashboard';
import { PermissionProvider } from '@/components/auth/PermissionProvider';

type ActiveView = 'chat' | 'dashboard' | 'compliance';

interface MainLayoutProps {
  className?: string;
}

const MainLayout: React.FC<MainLayoutProps> = ({ className }) => {
  const [activeView, setActiveView] = useState<ActiveView>('chat');

  const navigationItems = [
    { 
      id: 'chat' as const, 
      label: 'Chat', 
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-3.582 8-8 8a8.955 8.955 0 01-4.126-.98L3 20l1.98-5.874A8.955 8.955 0 013 12c0-4.418 3.582-8 8-8s8 3.582 8 8z" />
        </svg>
      )
    },
    { 
      id: 'dashboard' as const, 
      label: 'Dashboard', 
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
        </svg>
      )
    },
    { 
      id: 'compliance' as const, 
      label: 'Compliance', 
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
    },
  ];

  const renderContent = () => {
    switch (activeView) {
      case 'chat':
        return <ChatLayout />;
      case 'dashboard':
        return (
          <div className="h-full overflow-auto">
            <DemoDashboard className="p-6" />
          </div>
        );
      case 'compliance':
        return (
          <div className="h-full bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <ComplianceDashboard />
          </div>
        );
      default:
        return <ChatLayout />;
    }
  };

  return (
    <PermissionProvider user="demo-user">
      <div className={cn('min-h-screen bg-gray-100', className)}>
        {/* Top Navigation */}
        <nav className="bg-white shadow-sm border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              {/* Logo */}
              <div className="flex items-center gap-3">
                <img 
                  src="/kubechat-logo.png" 
                  alt="KubeChat Logo" 
                  className="h-8 w-auto"
                />
              </div>

              {/* Navigation Tabs */}
              <div className="flex space-x-1">
                {navigationItems.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setActiveView(item.id)}
                    className={cn(
                      'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                      activeView === item.id
                        ? 'bg-blue-100 text-blue-700 border border-blue-200'
                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                    )}
                  >
                    {item.icon}
                    {item.label}
                  </button>
                ))}
              </div>

              {/* User Info */}
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <div className="w-6 h-6 bg-green-500 rounded-full"></div>
                <span>Connected</span>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="h-[calc(100vh-8rem)]">
            {renderContent()}
          </div>
        </main>
      </div>
    </PermissionProvider>
  );
};

export default MainLayout;