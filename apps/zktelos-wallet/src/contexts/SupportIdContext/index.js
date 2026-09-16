import { createContext, useState, useEffect, useCallback } from 'react';
import { v4 as uuidv4 } from 'uuid';

const SupportIdContext = createContext({ supportId: null });

export default SupportIdContext;

export const SupportIdContextProvider = ({ children }) => {
  const [supportId, setSupportId] = useState(null);

  const updateSupportId = useCallback(() => {
    setSupportId(uuidv4());
  }, []);

  useEffect(() => {
    updateSupportId();
  }, [updateSupportId]);

  return (
    <SupportIdContext.Provider value={{ supportId, updateSupportId }}>
      {children}
    </SupportIdContext.Provider>
  );
};
