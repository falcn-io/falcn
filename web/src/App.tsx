import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout }    from '@/components/Layout';
import { Dashboard } from '@/pages/Dashboard';
import { Scanner }   from '@/pages/Scanner';
import { Threats }   from '@/pages/Threats';
import { Reports }   from '@/pages/Reports';
import { Activity }  from '@/pages/Activity';
import { Settings }  from '@/pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index         element={<Dashboard />} />
          <Route path="scanner"  element={<Scanner />}   />
          <Route path="threats"  element={<Threats />}   />
          <Route path="reports"  element={<Reports />}   />
          <Route path="activity" element={<Activity />}  />
          <Route path="settings" element={<Settings />}  />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
