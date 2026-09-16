import React, { useContext } from 'react';
import { HashRouter, Switch, Route, Redirect, useLocation } from 'react-router-dom';

// import { useIdleTimer } from 'react-idle-timer';

import Tabs from 'containers/Tabs';
import TransactionModal from 'containers/TransactionModal';
import WalletModal from 'containers/WalletModal';
import AccountSetUpModal from 'containers/AccountSetUpModal';
import PasswordModal from 'containers/PasswordModal';
import SwapModal from 'containers/SwapModal';
import ConfirmLogoutModal from 'containers/ConfirmLogoutModal';
import SeedPhraseModal from 'containers/SeedPhraseModal';
import IncreasedLimitsModal from 'containers/IncreasedLimitsModal';
import RedeemGiftCardModal from 'containers/RedeemGiftCardModal';
import WrapModal from 'containers/WrapModal';

import Header from 'components/Header';
import ChangePasswordModal from 'components/ChangePasswordModal';
import DisablePasswordModal from 'components/DisablePasswordModal';
import ToastContainer from 'components/ToastContainer';
import Footer from 'components/Footer';
import Layout from 'components/Layout';
import PaymentLinkModal from 'components/PaymentLinkModal';

import WelcomeModal from 'containers/WelcomeModal';
import Deposit from 'pages/Deposit';
import Transfer from 'pages/Transfer';
import Withdraw from 'pages/Withdraw';
import History from 'pages/History';
import Payment from 'pages/Payment';
import Home from 'pages/Home';
import Settings from 'pages/Settings';

import ContextsProvider, { ZkAccountContext } from 'contexts';

// Automatic error and navigation telemetry is disabled for the privacy wallet.
// Existing captureException calls have no initialized transport.

const Routes = ({ params }) => (
  <Switch>
    <Route exact strict path="/home">
      <Home />
    </Route>
    <Route exact strict path="/deposit">
      <Deposit />
    </Route>
    <Route exact strict path="/transfer">
      <Transfer />
    </Route>
    <Route exact strict path="/withdraw">
      <Withdraw />
    </Route>
    <Route exact strict path="/history">
      <History />
    </Route>
    <Route exact strict path="/settings">
      <Settings />
    </Route>
    <Redirect to={'/home' + params} />
  </Switch>
);

const MainApp = () => {
  const location = useLocation();
  const [welcomeOpen, setWelcomeOpen] = React.useState(
    () => !localStorage.getItem('welcomeSeen') && !localStorage.getItem('seed')
  );
  // useIdleTimer({
  //   timeout: Number(process.env.REACT_APP_LOCK_TIMEOUT) || (1000 * 60 * 15),
  //   onIdle: () => lockAccount(),
  // });

  return (
    <>
      {/* {isDemo && <DemoBanner />} */}
      {/* <BannerWithCountdown /> */}
      <Layout header={<Header />} footer={<Footer />}>
        <Tabs />
        <Routes params={location.search} />
      </Layout>
      <WelcomeModal isOpen={welcomeOpen} onClose={() => setWelcomeOpen(false)} />
      <TransactionModal />
      <WalletModal />
      <AccountSetUpModal />
      <RedeemGiftCardModal />
      <PasswordModal />
      <ChangePasswordModal />
      <ToastContainer />
      <SwapModal />
      <ConfirmLogoutModal />
      <SeedPhraseModal />
      <IncreasedLimitsModal />
      <DisablePasswordModal />
      <PaymentLinkModal />
      <WrapModal />
    </>
  );
}

export default () => (
  <HashRouter>
    <Switch>
      <Route exact strict path="/payment/:address">
        <Payment />
      </Route>
      <Route>
        <ContextsProvider>
          <MainApp />
        </ContextsProvider>
      </Route>
    </Switch>
  </HashRouter>
);
