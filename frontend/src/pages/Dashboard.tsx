import React from 'react';
import {
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  CardHeader,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  TrendingUp as TrendingUpIcon,
} from '@mui/icons-material';

const Dashboard: React.FC = () => {
  // Mock data - in real app this would come from API
  const stats = {
    totalThreats: 1543,
    activeThreats: 89,
    verifiedThreats: 1201,
    recentThreats: 23,
  };

  const recentAlerts = [
    { id: 1, title: 'Suspicious IP Activity', severity: 'high', time: '2 minutes ago' },
    { id: 2, title: 'Malware Detected', severity: 'critical', time: '15 minutes ago' },
    { id: 3, title: 'Phishing Attempt', severity: 'medium', time: '1 hour ago' },
  ];

  const StatCard = ({ title, value, icon, color }: any) => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="h4" component="div" color={color}>
              {value}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {title}
            </Typography>
          </Box>
          <Box sx={{ color }}>
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      
      <Grid container spacing={3}>
        {/* Statistics Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Threats"
            value={stats.totalThreats.toLocaleString()}
            icon={<SecurityIcon fontSize="large" />}
            color="primary.main"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Active Threats"
            value={stats.activeThreats}
            icon={<WarningIcon fontSize="large" />}
            color="warning.main"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Verified Threats"
            value={stats.verifiedThreats.toLocaleString()}
            icon={<CheckCircleIcon fontSize="large" />}
            color="success.main"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Recent (24h)"
            value={stats.recentThreats}
            icon={<TrendingUpIcon fontSize="large" />}
            color="info.main"
          />
        </Grid>

        {/* Recent Alerts */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: '400px' }}>
            <Typography variant="h6" gutterBottom>
              Recent Alerts
            </Typography>
            <Box>
              {recentAlerts.map((alert) => (
                <Box
                  key={alert.id}
                  sx={{
                    p: 2,
                    mb: 1,
                    border: '1px solid',
                    borderColor: 'grey.300',
                    borderRadius: 1,
                  }}
                >
                  <Typography variant="subtitle1">{alert.title}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Severity: {alert.severity} • {alert.time}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Paper>
        </Grid>

        {/* Threat Distribution */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: '400px' }}>
            <Typography variant="h6" gutterBottom>
              Threat Distribution
            </Typography>
            <Box sx={{ p: 2 }}>
              <Typography variant="body1">
                Chart visualization would go here
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Real-time threat intelligence visualization
              </Typography>
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;