import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Button } from '@/components/ui/button';

describe('Accessibility Tests', () => {
  test('Button component has proper accessibility attributes', () => {
    render(<Button>Accessible Button</Button>);
    const button = screen.getByRole('button', { name: /accessible button/i });
    expect(button).toBeInTheDocument();
    expect(button).toHaveAttribute('type', 'button');
  });

  test('Button variants maintain accessibility', () => {
    render(
      <div>
        <Button variant="primary">Primary</Button>
        <Button variant="secondary">Secondary</Button>
        <Button variant="destructive">Delete</Button>
        <Button variant="outline">Outline</Button>
        <Button variant="ghost">Ghost</Button>
      </div>
    );
    
    expect(screen.getByRole('button', { name: /primary/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /secondary/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /outline/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /ghost/i })).toBeInTheDocument();
  });

  test('Disabled button is properly marked as disabled', () => {
    render(<Button disabled>Disabled Button</Button>);
    const button = screen.getByRole('button');
    expect(button).toBeDisabled();
  });

  test('Form elements have proper labels and descriptions', () => {
    render(
      <form>
        <label htmlFor="search-input">Search Conversations</label>
        <input
          id="search-input"
          type="text"
          placeholder="Search..."
          aria-describedby="search-help"
        />
        <div id="search-help">
          Enter keywords to search through your conversations
        </div>
        <Button type="submit">Search</Button>
      </form>
    );

    const input = screen.getByLabelText(/search conversations/i);
    const helpText = screen.getByText(/enter keywords to search/i);
    const submitButton = screen.getByRole('button', { name: /search/i });

    expect(input).toHaveAttribute('aria-describedby', 'search-help');
    expect(helpText).toHaveAttribute('id', 'search-help');
    expect(submitButton).toHaveAttribute('type', 'submit');
  });

  test('Keyboard navigation works for interactive elements', async () => {
    const user = userEvent.setup();
    
    render(
      <div>
        <Button>First Button</Button>
        <Button>Second Button</Button>
        <input type="text" placeholder="Input field" />
        <Button>Last Button</Button>
      </div>
    );

    const firstButton = screen.getByRole('button', { name: /first button/i });
    const secondButton = screen.getByRole('button', { name: /second button/i });
    const input = screen.getByPlaceholderText(/input field/i);
    
    // Test tab navigation
    await user.tab();
    expect(firstButton).toHaveFocus();
    
    await user.tab();
    expect(secondButton).toHaveFocus();
    
    await user.tab();
    expect(input).toHaveFocus();
  });

  test('ARIA attributes are properly used', () => {
    render(
      <div>
        <div role="alert" aria-live="polite">
          Status message
        </div>
        <button aria-expanded="false" aria-controls="menu">
          Menu Button
        </button>
        <div id="menu" aria-hidden="true">
          Hidden menu content
        </div>
        <input
          type="text"
          aria-label="Search input"
          aria-describedby="search-description"
        />
        <div id="search-description">
          Search through your conversations
        </div>
      </div>
    );

    const alert = screen.getByRole('alert');
    const menuButton = screen.getByRole('button', { name: /menu button/i });
    const searchInput = screen.getByLabelText(/search input/i);
    const description = screen.getByText(/search through your conversations/i);

    expect(alert).toHaveAttribute('aria-live', 'polite');
    expect(menuButton).toHaveAttribute('aria-expanded', 'false');
    expect(menuButton).toHaveAttribute('aria-controls', 'menu');
    expect(searchInput).toHaveAttribute('aria-describedby', 'search-description');
    expect(description).toHaveAttribute('id', 'search-description');
  });

  test('Images have proper alt text', () => {
    render(
      <div>
        <img src="test.jpg" alt="Descriptive alt text" />
        <div role="img" aria-label="Decorative icon">
          <svg>
            <path d="..." />
          </svg>
        </div>
      </div>
    );

    const image = screen.getByAltText(/descriptive alt text/i);
    const svgIcon = screen.getByRole('img', { name: /decorative icon/i });

    expect(image).toHaveAttribute('alt', 'Descriptive alt text');
    expect(svgIcon).toHaveAttribute('aria-label', 'Decorative icon');
  });

  test('Headings maintain proper hierarchy', () => {
    render(
      <div>
        <h1>Main Heading</h1>
        <h2>Section Heading</h2>
        <h3>Subsection Heading</h3>
        <p>Content paragraph</p>
        <h2>Another Section</h2>
        <h3>Another Subsection</h3>
      </div>
    );

    const h1 = screen.getByRole('heading', { level: 1 });
    const h2Elements = screen.getAllByRole('heading', { level: 2 });
    const h3Elements = screen.getAllByRole('heading', { level: 3 });

    expect(h1).toHaveTextContent('Main Heading');
    expect(h2Elements).toHaveLength(2);
    expect(h3Elements).toHaveLength(2);
  });
});